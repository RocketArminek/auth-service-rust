use crate::domain::user::User;
use lazy_regex::Regex;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allowed,
    Denied,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operator {
    Equals,
    NotEquals,
    Regexp,
    Contains,
    StartsWith,
    EndsWith,
    Empty,
    NotEmpty,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub field: String,
    pub operator: Operator,
    pub value: Option<String>,
}

impl Condition {
    pub fn evaluate(&self, context: &PolicyContext) -> bool {
        let field_value = context.get_field_value(&self.field);

        match (&self.operator, &field_value, &self.value) {
            (Operator::Empty, Some(values), _) => values.is_empty(),
            (Operator::NotEmpty, Some(values), _) => !values.is_empty(),
            (Operator::Equals, Some(values), Some(compare_to)) => values.contains(compare_to),
            (Operator::NotEquals, Some(values), Some(compare_to)) => !values.contains(compare_to),
            (Operator::Regexp, Some(values), Some(pattern)) => {
                if let Ok(re) = Regex::new(pattern) {
                    values.iter().any(|v| re.is_match(v))
                } else {
                    false
                }
            }
            (Operator::Contains, Some(values), Some(compare_to)) => {
                values.iter().any(|v| v.contains(compare_to))
            }
            (Operator::StartsWith, Some(values), Some(compare_to)) => {
                values.iter().any(|v| v.starts_with(compare_to))
            }
            (Operator::EndsWith, Some(values), Some(compare_to)) => {
                values.iter().any(|v| v.ends_with(compare_to))
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Expression {
    Condition(Condition),
    Logical {
        operator: LogicalOperator,
        expressions: Vec<Expression>,
    },
}

impl Expression {
    pub fn evaluate(&self, context: &PolicyContext) -> bool {
        match self {
            Expression::Condition(condition) => condition.evaluate(context),
            Expression::Logical {
                operator,
                expressions,
            } => match operator {
                LogicalOperator::And => expressions.iter().all(|expr| expr.evaluate(context)),
                LogicalOperator::Or => expressions.iter().any(|expr| expr.evaluate(context)),
                LogicalOperator::Not => {
                    assert_eq!(
                        expressions.len(),
                        1,
                        "NOT operator should have exactly one child expression"
                    );
                    !expressions[0].evaluate(context)
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyStatement {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: Effect,
    pub expression: Expression,
}

impl PolicyStatement {
    pub fn evaluate(&self, context: &PolicyContext) -> Decision {
        if self.expression.evaluate(context) {
            match self.effect {
                Effect::Allow => Decision::Allowed,
                Effect::Deny => Decision::Denied,
            }
        } else {
            Decision::NotApplicable
        }
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub statements: Vec<PolicyStatement>,
}

impl Policy {
    pub fn evaluate(&self, context: &PolicyContext) -> Decision {
        let mut has_applicable = false;

        for statement in &self.statements {
            match statement.evaluate(context) {
                Decision::Denied => return Decision::Denied,
                Decision::Allowed => has_applicable = true,
                Decision::NotApplicable => {}
            }
        }

        if has_applicable {
            Decision::Allowed
        } else {
            Decision::Denied
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub user: User,
    pub user_roles: Vec<String>,
    pub user_permissions: HashMap<String, Vec<String>>,
    pub request: PolicyRequest,
}

impl PolicyContext {
    pub fn get_field_value(&self, field: &str) -> Option<Vec<String>> {
        let parts: Vec<&str> = field.split('.').collect();

        match parts.as_slice() {
            ["request", "host"] => Some(vec![self.request.host.clone()]),
            ["request", "path"] => Some(vec![self.request.path.clone()]),
            ["request", "method"] => Some(vec![self.request.method.clone()]),

            ["user", "id"] => Some(vec![self.user.id.to_string()]),
            ["user", "email"] => Some(vec![self.user.email.clone()]),
            ["user", "roles"] => Some(self.user_roles.clone()),

            ["user", "permissions", group] => self.user_permissions.get(*group).cloned(),
            ["user", "permissions"] => {
                let mut all_permissions = Vec::new();
                for perms in self.user_permissions.values() {
                    all_permissions.extend(perms.clone());
                }
                Some(all_permissions)
            }

            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRequest {
    pub host: String,
    pub path: String,
    pub method: String,
}
