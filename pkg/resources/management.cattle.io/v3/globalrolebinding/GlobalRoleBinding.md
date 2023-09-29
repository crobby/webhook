## Validation Checks

Note: all checks are bypassed if the GlobalRoleBinding is being deleted, or if only the metadata fields are being updated.

### Escalation Prevention

Users can only create/update GlobalRoleBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

This escalation checking currently prevents service accounts from modifying GlobalRoleBindings which give access to GlobalRoles which include permissions on downstream clusters (such as Admin, Restricted Admin, or GlobalRoles which use the `inheritedClusterRoles` field).

### Valid Global Role Reference

GlobalRoleBindings must refer to a valid global role (i.e. an existing `GlobalRole` object in the `management.cattle.io/v3` apiGroup).

### Invalid Fields - Update
Users cannot update the following fields after creation:
- `userName`
- `groupPrincipalName`
- `globalRoleName`


### Invalid Fields - Create
GlobalRoleBindings must have either `userName` or `groupPrincipalName`, but not both.
All RoleTemplates which are referred to in the `inheritedClusterRoles` field must exist and not be locked. 

## Mutation Checks

### On create

When a GlobalRoleBinding is created an owner reference is created on the binding referring to the backing GlobalRole defined by `globalRoleName`.