## How to run the example

```
docker compose up -d --build
```

1. Create a test user

```
curl -X POST http://localhost/v1/users \
  -H "Host: auth.localhost" \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "password": "Test#123",
    "role": "USER"
  }'
```

2. Login

```
curl -X POST http://localhost/v1/login \
  -H "Host: auth.localhost" \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "password": "Test#123"
  }'
```

3. Access the example app

```
curl -H "Host: app.localhost" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost
```

```
curl -X POST -H "Host: app.localhost" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test"}' \
  http://localhost/api/users
```

```
curl -X PUT -H "Host: app.localhost" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "updated"}' \
  http://localhost/api/users/123
```

```
curl -X DELETE -H "Host: app.localhost" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost/api/users/123
```

```
curl -X PATCH -H "Host: app.localhost" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "active"}' \
  http://localhost/any/other/path
```
