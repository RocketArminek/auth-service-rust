use auth_service::domain::policy::{
    Condition, Decision, Effect, Expression, LogicalOperator, Operator, Policy, PolicyContext,
    PolicyRequest, PolicyStatement,
};
use auth_service::domain::user::User;
use std::collections::HashMap;
use uuid::Uuid;

fn eq(field: &str, value: &str) -> Expression {
    Expression::Condition(Condition {
        field: field.to_string(),
        operator: Operator::Equals,
        value: Some(value.to_string()),
    })
}

fn regex(field: &str, pattern: &str) -> Expression {
    Expression::Condition(Condition {
        field: field.to_string(),
        operator: Operator::Regexp,
        value: Some(pattern.to_string()),
    })
}

fn contains(field: &str, value: &str) -> Expression {
    Expression::Condition(Condition {
        field: field.to_string(),
        operator: Operator::Contains,
        value: Some(value.to_string()),
    })
}

fn and(expressions: Vec<Expression>) -> Expression {
    Expression::Logical {
        operator: LogicalOperator::And,
        expressions,
    }
}

fn or(expressions: Vec<Expression>) -> Expression {
    Expression::Logical {
        operator: LogicalOperator::Or,
        expressions,
    }
}

fn not(expression: Expression) -> Expression {
    Expression::Logical {
        operator: LogicalOperator::Not,
        expressions: vec![expression],
    }
}

fn create_test_context() -> PolicyContext {
    let user = User::now_with_email_and_password(
        "test@example.com".to_string(),
        "passworD123#123##".to_string(),
        Some("Test".to_string()),
        Some("User".to_string()),
        Some(true),
    )
    .unwrap();

    let user_roles = vec!["USER".to_string(), "EDITOR".to_string()];

    let mut user_permissions = HashMap::new();
    user_permissions.insert(
        "blog".to_string(),
        vec!["read".to_string(), "create".to_string()],
    );
    user_permissions.insert("comment".to_string(), vec!["create".to_string()]);

    let request = PolicyRequest {
        host: "app.localhost".to_string(),
        path: "/v1/posts/123".to_string(),
        method: "GET".to_string(),
    };

    PolicyContext {
        user,
        user_roles,
        user_permissions,
        request,
    }
}

#[test]
fn test_condition_equals_operator() {
    let context = create_test_context();

    let condition = Condition {
        field: "request.host".to_string(),
        operator: Operator::Equals,
        value: Some("app.localhost".to_string()),
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "request.host".to_string(),
        operator: Operator::Equals,
        value: Some("other.localhost".to_string()),
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_condition_not_equals_operator() {
    let context = create_test_context();

    let condition = Condition {
        field: "request.method".to_string(),
        operator: Operator::NotEquals,
        value: Some("POST".to_string()),
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "request.method".to_string(),
        operator: Operator::NotEquals,
        value: Some("GET".to_string()),
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_condition_regexp_operator() {
    let context = create_test_context();

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::Regexp,
        value: Some(r"^/v1/posts/\d+$".to_string()),
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::Regexp,
        value: Some(r"^/v1/users/\d+$".to_string()),
    };

    assert!(!condition.evaluate(&context));

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::Regexp,
        value: Some(r"[".to_string()),
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_condition_contains_operator() {
    let context = create_test_context();

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::Contains,
        value: Some("posts".to_string()),
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::Contains,
        value: Some("users".to_string()),
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_condition_starts_with_operator() {
    let context = create_test_context();

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::StartsWith,
        value: Some("/v1".to_string()),
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::StartsWith,
        value: Some("/api".to_string()),
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_condition_ends_with_operator() {
    let context = create_test_context();

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::EndsWith,
        value: Some("/123".to_string()),
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "request.path".to_string(),
        operator: Operator::EndsWith,
        value: Some("/456".to_string()),
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_condition_empty_not_empty_operators() {
    let mut context = create_test_context();

    let condition = Condition {
        field: "user.roles".to_string(),
        operator: Operator::NotEmpty,
        value: None,
    };

    assert!(condition.evaluate(&context));

    context.user_roles = vec![];

    let condition = Condition {
        field: "user.roles".to_string(),
        operator: Operator::Empty,
        value: None,
    };

    assert!(condition.evaluate(&context));

    let condition = Condition {
        field: "user.roles".to_string(),
        operator: Operator::NotEmpty,
        value: None,
    };

    assert!(!condition.evaluate(&context));
}

#[test]
fn test_expression_condition() {
    let context = create_test_context();

    let expr = eq("request.host", "app.localhost");
    assert!(expr.evaluate(&context));

    let expr = eq("request.host", "wrong.host");
    assert!(!expr.evaluate(&context));
}

#[test]
fn test_expression_and() {
    let context = create_test_context();

    let expr = and(vec![
        eq("request.host", "app.localhost"),
        eq("request.method", "GET"),
    ]);

    assert!(expr.evaluate(&context));

    let expr = and(vec![
        eq("request.host", "app.localhost"),
        eq("request.method", "POST"),
    ]);

    assert!(!expr.evaluate(&context));
}

#[test]
fn test_expression_or() {
    let context = create_test_context();

    let expr = or(vec![
        eq("request.method", "POST"),
        eq("request.method", "GET"),
    ]);

    assert!(expr.evaluate(&context));

    let expr = or(vec![
        eq("request.method", "POST"),
        eq("request.method", "DELETE"),
    ]);

    assert!(!expr.evaluate(&context));
}

#[test]
fn test_expression_not() {
    let context = create_test_context();

    let expr = not(eq("request.method", "POST"));
    assert!(expr.evaluate(&context));

    let expr = not(eq("request.method", "GET"));
    assert!(!expr.evaluate(&context));
}

#[test]
fn test_expression_complex() {
    let context = create_test_context();

    let expr = or(vec![
        and(vec![
            eq("request.host", "app.localhost"),
            eq("request.method", "GET"),
        ]),
        and(vec![
            contains("request.path", "posts"),
            eq("user.roles", "EDITOR"),
        ]),
    ]);

    assert!(expr.evaluate(&context));

    let expr = not(and(vec![
        eq("request.host", "app.localhost"),
        eq("request.method", "POST"),
    ]));

    assert!(expr.evaluate(&context));
}

#[test]
fn test_policy_statement_allow_effect() {
    let context = create_test_context();

    let statement = PolicyStatement {
        id: Uuid::new_v4(),
        name: "Test Allow Statement".to_string(),
        description: Some("Test description".to_string()),
        effect: Effect::Allow,
        expression: eq("request.method", "GET"),
    };

    assert_eq!(statement.evaluate(&context), Decision::Allowed);

    let statement = PolicyStatement {
        id: Uuid::new_v4(),
        name: "Test Allow Statement".to_string(),
        description: Some("Test description".to_string()),
        effect: Effect::Allow,
        expression: eq("request.method", "POST"),
    };

    assert_eq!(statement.evaluate(&context), Decision::NotApplicable);
}

#[test]
fn test_policy_statement_deny_effect() {
    let context = create_test_context();

    let statement = PolicyStatement {
        id: Uuid::new_v4(),
        name: "Test Deny Statement".to_string(),
        description: Some("Test description".to_string()),
        effect: Effect::Deny,
        expression: eq("request.method", "POST"),
    };

    assert_eq!(statement.evaluate(&context), Decision::NotApplicable);

    let statement = PolicyStatement {
        id: Uuid::new_v4(),
        name: "Test Deny Statement".to_string(),
        description: Some("Test description".to_string()),
        effect: Effect::Deny,
        expression: eq("request.method", "GET"),
    };

    assert_eq!(statement.evaluate(&context), Decision::Denied);
}

#[test]
fn test_policy_with_multiple_statements() {
    let context = create_test_context();

    let policy = Policy {
        id: Uuid::new_v4(),
        name: "Test Policy".to_string(),
        description: Some("Test policy with multiple statements".to_string()),
        statements: vec![
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Allow GET".to_string(),
                description: Some("Allow GET method".to_string()),
                effect: Effect::Allow,
                expression: eq("request.method", "GET"),
            },
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Deny specific path".to_string(),
                description: Some("Deny access to admin path".to_string()),
                effect: Effect::Deny,
                expression: contains("request.path", "admin"),
            },
        ],
    };

    assert_eq!(policy.evaluate(&context), Decision::Allowed);

    let mut admin_context = context.clone();
    admin_context.request.path = "/v1/admin/settings".to_string();

    assert_eq!(policy.evaluate(&admin_context), Decision::Denied);

    let mut post_context = context.clone();
    post_context.request.method = "POST".to_string();

    assert_eq!(policy.evaluate(&post_context), Decision::Denied);
}

#[test]
fn test_policy_context_field_access() {
    let context = create_test_context();

    assert_eq!(
        context.get_field_value("request.host"),
        Some(vec!["app.localhost".to_string()])
    );
    assert_eq!(
        context.get_field_value("request.path"),
        Some(vec!["/v1/posts/123".to_string()])
    );
    assert_eq!(
        context.get_field_value("request.method"),
        Some(vec!["GET".to_string()])
    );

    assert_eq!(
        context.get_field_value("user.email"),
        Some(vec!["test@example.com".to_string()])
    );
    assert_eq!(
        context.get_field_value("user.id"),
        Some(vec![context.user.id.to_string()])
    );

    assert_eq!(
        context.get_field_value("user.roles"),
        Some(vec!["USER".to_string(), "EDITOR".to_string()])
    );

    assert_eq!(
        context.get_field_value("user.permissions.blog"),
        Some(vec!["read".to_string(), "create".to_string()])
    );

    let all_permissions = context.get_field_value("user.permissions").unwrap();
    assert_eq!(all_permissions.len(), 3);
    assert!(all_permissions.contains(&"read".to_string()));
    assert!(all_permissions.contains(&"create".to_string()));

    assert_eq!(context.get_field_value("invalid.field"), None);
}

#[test]
fn test_blog_policy_example() {
    let blog_policy = Policy {
        id: Uuid::new_v4(),
        name: "Blog Access Policy".to_string(),
        description: Some("Controls access to blog resources".to_string()),
        statements: vec![
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Allow list blog posts".to_string(),
                description: Some("Allow users to list blog posts".to_string()),
                effect: Effect::Allow,
                expression: and(vec![
                    eq("request.host", "app.localhost"),
                    regex("request.path", "^/v1/posts$"),
                    eq("request.method", "GET"),
                    eq("user.permissions.blog", "read"),
                ]),
            },
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Allow view blog post".to_string(),
                description: Some("Allow users to view specific blog posts".to_string()),
                effect: Effect::Allow,
                expression: and(vec![
                    eq("request.host", "app.localhost"),
                    regex("request.path", "^/v1/posts/\\d+$"),
                    eq("request.method", "GET"),
                    eq("user.permissions.blog", "read"),
                ]),
            },
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Allow create blog post".to_string(),
                description: Some("Allow users to create blog posts".to_string()),
                effect: Effect::Allow,
                expression: and(vec![
                    eq("request.host", "app.localhost"),
                    regex("request.path", "^/v1/posts$"),
                    eq("request.method", "POST"),
                    eq("user.permissions.blog", "create"),
                ]),
            },
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Allow edit blog post".to_string(),
                description: Some("Allow editors to edit blog posts".to_string()),
                effect: Effect::Allow,
                expression: and(vec![
                    eq("request.host", "app.localhost"),
                    regex("request.path", "^/v1/posts/\\d+$"),
                    or(vec![
                        eq("request.method", "PUT"),
                        eq("request.method", "PATCH"),
                    ]),
                    eq("user.roles", "EDITOR"),
                ]),
            },
            PolicyStatement {
                id: Uuid::new_v4(),
                name: "Deny draft access".to_string(),
                description: Some("Only editors can access draft posts".to_string()),
                effect: Effect::Deny,
                expression: and(vec![
                    regex("request.path", "^/v1/posts/drafts"),
                    not(eq("user.roles", "EDITOR")),
                ]),
            },
        ],
    };

    let mut reader_context = create_test_context();
    reader_context.user_roles = vec!["USER".to_string()];
    reader_context.user_permissions =
        HashMap::from([("blog".to_string(), vec!["read".to_string()])]);
    reader_context.request.path = "/v1/posts/123".to_string();
    reader_context.request.method = "GET".to_string();

    assert_eq!(blog_policy.evaluate(&reader_context), Decision::Allowed);

    let mut reader_drafts_context = reader_context.clone();
    reader_drafts_context.request.path = "/v1/posts/drafts".to_string();

    assert_eq!(
        blog_policy.evaluate(&reader_drafts_context),
        Decision::Denied
    );

    let mut editor_context = create_test_context();
    editor_context.user_roles = vec!["EDITOR".to_string()];
    editor_context.user_permissions = HashMap::from([(
        "blog".to_string(),
        vec!["read".to_string(), "create".to_string()],
    )]);
    editor_context.request.path = "/v1/posts/drafts".to_string();
    editor_context.request.method = "GET".to_string();

    assert_eq!(blog_policy.evaluate(&editor_context), Decision::Denied);

    let mut editor_edit_context = editor_context.clone();
    editor_edit_context.request.path = "/v1/posts/123".to_string();
    editor_edit_context.request.method = "PUT".to_string();

    assert_eq!(
        blog_policy.evaluate(&editor_edit_context),
        Decision::Allowed
    );

    let mut creator_context = create_test_context();
    creator_context.user_roles = vec!["USER".to_string()];
    creator_context.user_permissions =
        HashMap::from([("blog".to_string(), vec!["create".to_string()])]);
    creator_context.request.path = "/v1/posts".to_string();
    creator_context.request.method = "POST".to_string();

    assert_eq!(blog_policy.evaluate(&creator_context), Decision::Allowed);
}
