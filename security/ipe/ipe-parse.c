// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-prop-internal.h"
#include "ipe-hooks.h"
#include "ipe-parse.h"
#include "ipe-property.h"
#include "ipe-audit.h"

#include <linux/types.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/parser.h>
#include <linux/errno.h>
#include <linux/err.h>

#define ALLOW_ACTION	"ALLOW"
#define DENY_ACTION	"DENY"
#define COMMENT_CHAR	'#'
#define VER_FSTR	"%hu.%hu.%hu"

/* Internal Type Definitions */
enum property_priority {
	other = 0,
	action = 1,
	op = 2,
	default_action = 3,
	policy_ver = 4,
	policy_name = 5,
};

struct token {
	struct list_head	next_tok;
	const char		*key;
	enum property_priority	key_priority;
	const char		*val;
};

/* Utility Functions */
static inline bool is_quote(char c)
{
	return c == '"' || c == '\'';
}

static inline bool valid_token(char *s)
{
	return !s || !strpbrk(s, "\"\'");
}

static inline bool is_default(const struct token *t)
{
	return !t->val &&  t->key_priority == default_action;
}

static inline bool is_operation(const struct token *t)
{
	return t->val && t->key_priority == op;
}

static inline bool is_action(const struct token *t)
{
	return t->val && t->key_priority == action;
}

static inline bool is_name(const struct token *t)
{
	return t->val && t->key_priority == policy_name;
}

static inline bool is_ver(const struct token *t)
{
	return t->val && t->key_priority == policy_ver;
}

static int cmp_pri(void *priv, struct list_head *a, struct list_head *b)
{
	struct token *t_a = container_of(a, struct token, next_tok);
	struct token *t_b = container_of(b, struct token, next_tok);

	return t_b->key_priority - t_a->key_priority;
}

static char *trim_quotes(char *str)
{
	char s;
	size_t len;

	if (!str)
		return str;

	s = *str;

	if (is_quote(s)) {
		len = strlen(str) - 1;

		if (str[len] != s)
			return NULL;

		str[len] = '\0';
		++str;
	}

	return str;
}

/**
 * ipe_set_action: Set an action with error checking.
 * @src: Valid pointer to the source location to set wih the result
 * @set: Value to apply to @src, if valid
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Attempting to set something that is already set
 */
static int ipe_set_action(enum ipe_action *src, enum ipe_action set)
{
	if (*src != ipe_action_unset)
		return -EBADMSG;

	*src = set;

	return 0;
}

/**
 * ipe_insert_token: Allocate and append the key=value pair indicated by @val,
 *		     to the list represented by @head.
 * @val: Token to parse, of form "key=val".
 * @head: Head of the list to insert the token structure into.
 *
 * If "=val" is omitted, this function will succeed, and the value set will be
 * NULL.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid policy syntax
 * -ENOMEM - No Memory
 */
static int ipe_insert_token(char *val, struct list_head *head)
{
	char *key;
	substring_t match[MAX_OPT_ARGS];
	struct token *tok;
	const match_table_t prop_priorities = {
		{ policy_name,		IPE_HEADER_POLICY_NAME },
		{ policy_ver,		IPE_HEADER_POLICY_VERSION},
		{ op,			IPE_PROPERTY_OPERATION },
		{ default_action,	IPE_PROPERTY_DEFAULT },
		{ action,		IPE_PROPERTY_ACTION },
		{ other, NULL },
	};

	key = strsep(&val, "=");
	if (!key)
		return -EBADMSG;

	tok = kzalloc(sizeof(*tok), GFP_KERNEL);
	if (!tok)
		return -ENOMEM;

	tok->key = key;
	tok->val = trim_quotes(val);

	/* remap empty string */
	if (tok->val && !strlen(tok->val))
		tok->val = NULL;

	tok->key_priority = match_token(key, prop_priorities, match);
	INIT_LIST_HEAD(&tok->next_tok);

	list_add_tail(&tok->next_tok, head);

	return 0;
}

/**
 * ipe_tokenize_line: Parse a line of text into a list of token structures.
 * @line: Line to parse.
 * @list: Head of the list to insert the token structure into.
 *
 * The final result will be sorted in the priority order definted by
 * enum property_priorities to enforce policy structure.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid policy syntax
 * -ENOMEM - No Memory
 * -ENOENT - No tokens were parsed
 */
static int ipe_tokenize_line(char *line, struct list_head *list)
{
	int rc = 0;
	size_t i = 0;
	size_t len = 0;
	char *tok = NULL;
	char quote = '\0';

	len = strlen(line);

	for (i = 0; i < len; ++i) {
		if (quote == '\0' && is_quote(line[i])) {
			quote = line[i];
			continue;
		}

		if (quote != '\0' && line[i] == quote) {
			quote = '\0';
			continue;
		}

		if (quote == '\0' && line[i] == COMMENT_CHAR) {
			tok = NULL;
			break;
		}

		if (isgraph(line[i]) && !tok)
			tok = &line[i];

		if (quote == '\0' && isspace(line[i])) {
			line[i] = '\0';

			if (!tok)
				continue;

			rc = ipe_insert_token(tok, list);
			if (rc != 0)
				return rc;

			tok = NULL;
		}
	}

	if (quote != '\0')
		return -EBADMSG;

	if (tok)
		ipe_insert_token(tok, list);

	if (list_empty(list))
		return -ENOENT;

	list_sort(NULL, list, cmp_pri);

	return 0;
}

static inline int ipe_parse_version(const char *val, struct ipe_pol_ver *ver)
{
	if (sscanf(val, VER_FSTR, &ver->major, &ver->minor, &ver->rev) != 3)
		return -EBADMSG;

	return 0;
}

/**
 * ipe_parse_action: Given a token, parse the value as if it were an 'action'
 *		     token.
 * @action: Token to parse to determine the action.
 *
 * Action tokens are of the form: action=(ALLOW|DENY) for more information
 * about IPE policy, please see the documentation.
 *
 * Return:
 * ipe_action_allow - OK
 * ipe_action_deny - OK
 * ipe_action_unset - ERR
 */
static enum ipe_action ipe_parse_action(struct token *action)
{
	if (!action->val)
		return ipe_action_unset;
	else if (!strcmp(action->val, ALLOW_ACTION))
		return ipe_action_allow;
	else if (!strcmp(action->val, DENY_ACTION))
		return ipe_action_deny;

	return ipe_action_unset;
}

/**
 * ipe_parse_op: Given a token, parse the value as if it were an 'op' token.
 * @op: Token to parse to determine the operation.
 *
 * "op" tokens are of the form: op=(EXECUTE|FIRMWARE|KEXEC_IMAGE|...)
 * for more information about IPE policy, please see the documentation.
 *
 * Return:
 * ipe_op_max - ERR
 * otherwise - OK
 */
static enum ipe_op ipe_parse_op(struct token *op)
{
	substring_t match[MAX_OPT_ARGS];
	const match_table_t ops = {
		{ ipe_op_execute,		IPE_OP_EXECUTE },
		{ ipe_op_firmware,		IPE_OP_FIRMWARE },
		{ ipe_op_kexec_image,		IPE_OP_KEXEC_IMAGE },
		{ ipe_op_kexec_initramfs,	IPE_OP_KEXEC_INITRAMFS },
		{ ipe_op_x509,			IPE_OP_X509_CERTIFICATE },
		{ ipe_op_policy,		IPE_OP_POLICY },
		{ ipe_op_kmodule,		IPE_OP_KMODULE },
		{ ipe_op_kernel_read,		IPE_OP_KERNEL_READ },
		{ ipe_op_max,			NULL },
	};

	return match_token((char *)op->val, ops, match);
}

/**
 * ipe_set_default: Set the default of the policy, at various scope levels
 *		    depending on the value of op.
 * @op: Operation that was parsed.
 * @pol: Policy to modify with the newly-parsed default action.
 * @a: Action token (see parse_action) to parse to determine
 *     the default.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid policy format
 */
static int ipe_set_default(enum ipe_op op, struct ipe_policy *pol,
			   struct token *a)
{
	int rc = 0;
	size_t i = 0;
	enum ipe_action act = ipe_parse_action(a);

	if (act == ipe_action_unset)
		return -EBADMSG;

	if (op == ipe_op_max)
		return ipe_set_action(&pol->def, act);

	if (op == ipe_op_kernel_read) {
		for (i = ipe_op_firmware; i <= ipe_op_kmodule; ++i) {
			rc = ipe_set_action(&pol->ops[i].def, act);
			if (rc != 0)
				return rc;
		}
		return 0;
	}

	return ipe_set_action(&pol->ops[op].def, act);
}

/**
 * ipe_parse_default: Parse a default statement of an IPE policy modify @pol
 *		      with the proper changes
 * @tokens: List of tokens parsed from the line
 * @pol: Policy to modify with the newly-parsed default action
 *
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid policy format
 * -ENOENT - Unknown policy structure
 */
static int ipe_parse_default(struct list_head *tokens,
			     struct ipe_policy *pol)
{
	struct token *f = NULL;
	struct token *s = NULL;
	struct token *t = NULL;
	enum ipe_op i = ipe_op_max;

	f = list_first_entry(tokens, struct token, next_tok);
	s = list_next_entry(f, next_tok);
	if (is_action(s))
		return ipe_set_default(ipe_op_max, pol, s);

	i = ipe_parse_op(s);
	if (i == ipe_op_max)
		return -ENOENT;

	t = list_next_entry(s, next_tok);
	if (is_action(t)) {
		t = list_next_entry(s, next_tok);
		return ipe_set_default(i, pol, t);
	}

	return -ENOENT;
}

/**
 * ipe_free_token_list - Free a list of tokens, and then reinitialize @list
 *			 dropping all tokens.
 * @list: List to be freed.
 */
static void ipe_free_token_list(struct list_head *list)
{
	struct token *ptr, *next;

	list_for_each_entry_safe(ptr, next, list, next_tok)
		kfree(ptr);

	INIT_LIST_HEAD(list);
}

/**
 * ipe_free_prop - Deallocator for an ipe_prop_container structure.
 * @cont: Object to free.
 */
static void ipe_free_prop(struct ipe_prop_container *cont)
{
	if (IS_ERR_OR_NULL(cont))
		return;

	if (cont->prop->free_val)
		cont->prop->free_val(&cont->value);
	kfree(cont);
}

/**
 * ipe_alloc_prop: Allocator for a ipe_prop_container structure.
 * @tok: Token structure representing the "key=value" pair of the property.
 *
 * Return:
 * Pointer to ipe_rule - OK
 * ERR_PTR(-ENOMEM) - Allocation failed
 */
static struct ipe_prop_container *ipe_alloc_prop(const struct token *tok)
{
	int rc = 0;
	const struct ipe_property *prop = NULL;
	struct ipe_prop_container *cont = NULL;

	prop = ipe_lookup_prop(tok->key);
	if (!prop) {
		rc = -ENOENT;
		goto err;
	}

	cont = kzalloc(sizeof(*cont), GFP_KERNEL);
	if (!cont) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&cont->next);

	rc = prop->parse(tok->val, &cont->value);
	if (rc != 0)
		goto err;

	cont->prop = prop;

	return cont;
err:
	ipe_free_prop(cont);
	return ERR_PTR(rc);
}

/**
 * ipe_free_rule: Deallocator for an ipe_rule structure.
 * @rule: Object to free.
 */
static void ipe_free_rule(struct ipe_rule *rule)
{
	struct ipe_prop_container *ptr;
	struct list_head *l_ptr, *l_next;

	if (IS_ERR_OR_NULL(rule))
		return;

	list_for_each_safe(l_ptr, l_next, &rule->props) {
		ptr = container_of(l_ptr, struct ipe_prop_container, next);
		list_del(l_ptr);
		ipe_free_prop(ptr);
	}

	kfree(rule);
}

/**
 * ipe_alloc_rule: Allocate a ipe_rule structure, for operation @op, parsed
 *		   from the first token in list @head.
 * @op: Operation parsed from the first token in @head.
 * @t: The first token in @head that was parsed.
 * @head: List of remaining tokens to parse.
 *
 * Return:
 * Valid ipe_rule pointer - OK
 * ERR_PTR(-EBADMSG) - Invalid syntax
 * ERR_PTR(-ENOMEM) - Out of memory
 */
static struct ipe_rule *ipe_alloc_rule(enum ipe_op op, struct token *t,
				       struct list_head *head)
{
	int rc = 0;
	struct token *ptr;
	enum ipe_action act;
	struct ipe_rule *rule = NULL;
	struct ipe_prop_container *prop = NULL;

	ptr = list_next_entry(t, next_tok);
	if (!is_action(ptr)) {
		rc = -EBADMSG;
		goto err;
	}

	act = ipe_parse_action(ptr);
	if (act == ipe_action_unset) {
		rc = -EBADMSG;
		goto err;
	}

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&rule->props);
	INIT_LIST_HEAD(&rule->next);
	rule->action = act;
	rule->op = op;

	list_for_each_entry_continue(ptr, head, next_tok) {
		prop = ipe_alloc_prop(ptr);

		if (IS_ERR(prop)) {
			rc = PTR_ERR(prop);
			goto err;
		}

		list_add_tail(&prop->next, &rule->props);
	}

	return rule;
err:
	ipe_free_prop(prop);
	ipe_free_rule(rule);
	return ERR_PTR(rc);
}

/**
 * ipe_dup_prop: Duplicate an ipe_prop_container structure
 * @p: Container to duplicate.
 *
 * This function is used to duplicate individual properties within a rule.
 * It should only be called in operations that actually map to one or more
 * operations.
 *
 * Return:
 * Valid ipe_prop_container - OK
 * ERR_PTR(-ENOMEM) - Out of memory
 * Other Errors - see various property duplicator functions
 */
static
struct ipe_prop_container *ipe_dup_prop(const struct ipe_prop_container *p)
{
	int rc = 0;
	struct ipe_prop_container *dup;

	dup = kzalloc(sizeof(*dup), GFP_KERNEL);
	if (!dup) {
		rc = -ENOMEM;
		goto err;
	}

	dup->prop = p->prop;
	INIT_LIST_HEAD(&dup->next);

	rc = p->prop->dup(p->value, &dup->value);
	if (rc != 0)
		goto err;

	return dup;
err:
	ipe_free_prop(dup);
	return ERR_PTR(rc);
}

/**
 * ipe_dup_rule: Duplicate a policy rule, used for pseudo hooks like
 *		 KERNEL_READ to map a policy rule across all hooks.
 * @r: Rule to duplicate.
 *
 * Return:
 * valid ipe_rule - OK
 * ERR_PTR(-ENOMEM) - Out of memory
 * Other Errors - See ipe_dup_prop
 */
static struct ipe_rule *ipe_dup_rule(const struct ipe_rule *r)
{
	int rc = 0;
	struct ipe_rule *dup;
	struct ipe_prop_container *ptr;

	dup = kzalloc(sizeof(*dup), GFP_KERNEL);
	if (!dup) {
		rc = -ENOMEM;
		goto err;
	}

	dup->op = r->op;
	dup->action = r->action;
	INIT_LIST_HEAD(&dup->props);
	INIT_LIST_HEAD(&dup->next);

	list_for_each_entry(ptr, &r->props, next) {
		struct ipe_prop_container *prop2;

		prop2 = ipe_dup_prop(ptr);
		if (IS_ERR(prop2)) {
			rc = PTR_ERR(prop2);
			goto err;
		}

		list_add_tail(&prop2->next, &dup->props);
	}

	return dup;
err:
	ipe_free_rule(dup);
	return ERR_PTR(rc);
}

/**
 * ipe_free_policy: Deallocate an ipe_policy structure.
 * @pol: Policy to free.
 */
void ipe_free_policy(struct ipe_policy *pol)
{
	size_t i;
	struct ipe_rule *ptr;
	struct ipe_rule_table *op;
	struct list_head *l_ptr, *l_next;

	if (IS_ERR_OR_NULL(pol))
		return;

	for (i = 0; i < ARRAY_SIZE(pol->ops); ++i) {
		op = &pol->ops[i];

		list_for_each_safe(l_ptr, l_next, &op->rules) {
			ptr = list_entry(l_ptr, struct ipe_rule, next);
			list_del(l_ptr);
			ipe_free_rule(ptr);
		}
	}

	kfree(pol->policy_name);
	kfree(pol);
}

/**
 * ipe_alloc_policy: Give a list of tokens representing the first line of the
 *		     token, attempt to parse it as an IPE policy header, and
 *		     allocate a policy structure based on those values.
 * @tokens: List of tokens parsed from the first line of the policy
 *
 * Return:
 * Valid ipe_policy pointer - OK
 * ERR_PTR(-ENOMEM) - Out of memory
 * ERR_PTR(-EBADMSG) - Invalid policy syntax
 */
static struct ipe_policy *ipe_alloc_policy(struct list_head *tokens)
{
	size_t i;
	int rc = 0;
	struct token *name = NULL;
	struct token *ver = NULL;
	struct ipe_policy *lp = NULL;

	name = list_first_entry(tokens, struct token, next_tok);
	if (!is_name(name)) {
		rc = -EBADMSG;
		goto err;
	}

	if (list_is_singular(tokens)) {
		rc = -EBADMSG;
		goto err;
	}

	ver = list_next_entry(name, next_tok);
	if (!is_ver(ver)) {
		rc = -EBADMSG;
		goto err;
	}

	lp = kzalloc(sizeof(*lp), GFP_KERNEL);
	if (!lp) {
		rc = -ENOMEM;
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(lp->ops); ++i) {
		lp->ops[i].def = ipe_action_unset;
		INIT_LIST_HEAD(&lp->ops[i].rules);
	}

	lp->policy_name = kstrdup(name->val, GFP_KERNEL);
	if (!lp->policy_name) {
		rc = -ENOMEM;
		goto err;
	}

	rc = ipe_parse_version(ver->val, &lp->policy_version);
	if (rc != 0)
		goto err;

	lp->def = ipe_action_unset;

	return lp;
err:
	ipe_free_policy(lp);
	return ERR_PTR(rc);
}

/**
 * ipe_add_rule_for_range: Given a ipe_rule @r, duplicate @r and add the rule
 *			   to @pol for the operation range @start to @end.
 * @start: The starting point of the range to add the rule to.
 * @end: The ending point of the range to add the rule to.
 * @r: The rule to copy.
 * @pol: Policy structure to modify with the result.
 *
 * This is @start to @end, inclusive. @r is still valid after this function,
 * and should be freed if appropriate.
 *
 * Return:
 * 0 - OK
 * Other Errors - See ipe_dup_prop
 */
static int ipe_add_rule_for_range(enum ipe_op start, enum ipe_op end,
				  struct ipe_rule *r, struct ipe_policy *pol)
{
	enum ipe_op i;
	struct ipe_rule *cpy = NULL;

	for (i = start; i <= end; ++i) {
		cpy = ipe_dup_rule(r);
		if (IS_ERR(cpy))
			return PTR_ERR(cpy);

		list_add_tail(&cpy->next, &pol->ops[i].rules);
	}

	return 0;
}

/**
 * ipe_parse_line: Given a list of tokens, attempt to parse it into a rule
 *		   structure, and add it to the passed-in ipe_policy structure.
 * @tokens: List of tokens that were parsed.
 * @pol: Policy structure to modify with the result.
 *
 * Return:
 * 0 - OK
 * -ENOENT - Unrecognized property
 * -ENOMEM - Out of memory
 * Other Errors - See ipe_dup_prop
 */
static int ipe_parse_line(struct list_head *tokens,
			  struct ipe_policy *pol)
{
	int rc = 0;
	struct token *f;
	enum ipe_op i = ipe_op_max;
	struct ipe_rule *rule = NULL;

	f = list_first_entry(tokens, struct token, next_tok);

	switch (f->key_priority) {
	case default_action:
		rc = ipe_parse_default(tokens, pol);
		break;
	case op:
		i = ipe_parse_op(f);
		if (i == ipe_op_max)
			return -ENOENT;

		if (list_is_singular(tokens))
			return -EBADMSG;

		rule = ipe_alloc_rule(i, f, tokens);
		if (IS_ERR(rule)) {
			rc = PTR_ERR(rule);
			goto cleanup;
		}

		if (i == ipe_op_kernel_read) {
			rc = ipe_add_rule_for_range(ipe_op_firmware,
						    ipe_op_kmodule, rule, pol);
			if (rc != 0)
				goto cleanup;
		} else {
			list_add_tail(&rule->next, &pol->ops[i].rules);
			rule = NULL;
		}
		break;
	default:
		return -ENOENT;
	}

cleanup:
	ipe_free_rule(rule);
	return rc;
}

/**
 * ipe_remap_policy_defaults: Remap all defaults not specified by policy to
 *			      'allow' to preserve compatibility.
 * @p: Policy to modify.
 *
 * This function's behavior changes when ipe_strict_parse is set. When
 * the strict parser is enabled, this function will break backwards policy
 * compatibility, erroring on an unset default.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - (Only with strict parse) A default was left unset.
 */
static int ipe_remap_policy_defaults(struct ipe_policy *p)
{
	size_t i;

	if (p->def == ipe_action_unset) {
		for (i = 0; i < ARRAY_SIZE(p->ops); ++i) {
			if (p->ops[i].def == ipe_action_unset) {
				ipe_audit_unset_remap((enum ipe_op)i);
				if (ipe_strict_parse)
					return -EBADMSG;
				p->ops[i].def = ipe_action_allow;
			}
		}
	}

	return 0;
}

/**
 * ipe_parse_policy: Given a string, parse the string into an IPE policy
 *		     structure.
 * @policy: NULL terminated string to parse.
 *
 * This function's behavior changes when ipe_strict_parse is set. When the
 * strict parser is enabled, this function will break backwards policy
 * compatibility, erroring on unknown syntax. This function will modify
 * @policy.
 *
 * Return:
 * Valid ipe_policy structure - OK
 * ERR_PTR(-EBADMSG) - Invalid Policy Syntax (Unrecoverable)
 * ERR_PTR(-ENOMEM) - Out of Memory
 */
struct ipe_policy *ipe_parse_policy(char *policy)
{
	int rc = 0;
	size_t i = 1;
	char *p = NULL;
	LIST_HEAD(t_list);
	struct ipe_policy *local_p = NULL;

	while ((p = strsep(&policy, "\n\0")) != NULL) {
		rc = ipe_tokenize_line(p, &t_list);
		if (rc == -ENOENT) {
			++i;
			continue;
		}
		if (rc != 0)
			goto err;

		if (!local_p) {
			local_p = ipe_alloc_policy(&t_list);
			if (IS_ERR(local_p)) {
				rc = PTR_ERR(local_p);
				goto err;
			}
		} else {
			rc = ipe_parse_line(&t_list, local_p);
			if (rc == -ENOENT) {
				pr_warn("failed to parse line %zu, ignoring",
					i);
				if (ipe_strict_parse) {
					rc = -EBADMSG;
					goto err;
				}
			} else if (rc != 0) {
				goto err;
			}
		}

		ipe_free_token_list(&t_list);
		++i;
	}

	rc = ipe_remap_policy_defaults(local_p);
	if (rc != 0)
		goto err;

	return local_p;
err:
	ipe_free_token_list(&t_list);
	ipe_free_policy(local_p);
	return ERR_PTR(rc);
}
