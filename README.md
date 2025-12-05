## api endpoints

### authentication

**register user**
```
POST /api/users/register/
```
body:
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "first_name": "test",
  "last_name": "user",
  "password": "1qa@WS#ED3ed",
  "password_confirm": "1qa@WS#ED3ed"
}
```
returns jwt tokens. new users get "user" role by default.

**login**
```
POST /api/users/login/
```
body:
```json
{
  "username": "testuser",
  "password": "1qa@WS#ED3ed"
}
```

### user endpoints (requires auth)

**get current user**
```
GET /api/users/me/
```
headers: `Authorization: Bearer <token>`

**update current user**
```
PUT /api/users/me/
```
headers: `Authorization: Bearer <token>`
body:
```json
{
  "email": "newemail@example.com",
  "first_name": "new",
  "last_name": "name"
}
```

**delete account**
```
DELETE /api/users/me/
```
headers: `Authorization: Bearer <token>`

**list all users**
```
GET /api/users/list_users/
```
headers: `Authorization: Bearer <token>`
returns list of all users with their roles.

### role management (admin only)

**update user roles**
```
PUT /api/users/{user_id}/roles/
```
headers: `Authorization: Bearer <token>`
body:
```json
{
  "roles": ["User", "Admin"]
}
```
only admins can update roles.

**list available roles**
```
GET /api/users/roles/available/
```
headers: `Authorization: Bearer <token>`
returns all available roles.

**list roles (admin only)**
```
GET /api/roles/
```
headers: `Authorization: Bearer <token>`
admin only endpoint.

## roles

- **user**: default role for all new registrations. can access basic endpoints.
- **admin**: can manage user roles and access admin endpoints. must be assigned by existing admin.

## password requirements

- minimum 8 characters
- at least one uppercase letter
- at least one number