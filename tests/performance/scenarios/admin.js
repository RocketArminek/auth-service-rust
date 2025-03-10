import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
    cloud: {
        projectID: 3737499,
    },
    stages: [
        { duration: '30s', target: 10 },  // Ramp up to 10 admin users
        { duration: '1m', target: 10 },   // Stay at 10 admin users
        { duration: '30s', target: 0 },   // Ramp down
    ],
    thresholds: {
        http_req_failed: ['rate==0.0'],
        checks: ['rate==1.0'],
        http_req_duration: ['p(95)<20', 'avg<10', 'max<300'],
        errors: ['rate<0.01'],
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export function setup() {
    const email = 'admin@example.com';
    const password = 'Admin#123*';

    const loginResponse = http.post(`${BASE_URL}/v1/login`, JSON.stringify({
        email: email,
        password: password,
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(loginResponse, {
        'admin login successful': (r) => r.status === 200,
    });

    return JSON.parse(loginResponse.body);
}

export default function (data) {
    const accessToken = data.accessToken.value;

    const getUsersResponse = http.get(`${BASE_URL}/v1/restricted/users?page=1&limit=10`, {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
        },
    });

    check(getUsersResponse, {
        'get users successful': (r) => r.status === 200,
    });

    const createUserResponse = http.post(
        `${BASE_URL}/v1/restricted/users`,
        JSON.stringify({
            email: `test_${Date.now()}@example.com`,
            password: 'Test#pass123',
            role: 'USER',
        }),
        {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        }
    );

    check(createUserResponse, {
        'create user successful': (r) => r.status === 201,
    });

    if (createUserResponse.status === 201) {
        const userId = JSON.parse(createUserResponse.body).id;
        const getUserResponse = http.get(
            `${BASE_URL}/v1/restricted/users/${userId}`,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                },
            }
        );

        check(getUserResponse, {
            'get user successful': (r) => r.status === 200,
        });

        const updateUserResponse = http.put(
            `${BASE_URL}/v1/restricted/users/${userId}`,
            JSON.stringify({
                firstName: 'Updated',
                lastName: 'User',
                avatarPath: null,
            }),
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        check(updateUserResponse, {
            'update user successful': (r) => r.status === 200,
        });

        const deleteUserResponse = http.del(
            `${BASE_URL}/v1/restricted/users/${userId}`,
            null,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                },
            }
        );

        check(deleteUserResponse, {
            'delete user successful': (r) => r.status === 200,
        });
    }

    const getSessionsResponse = http.get(`${BASE_URL}/v1/restricted/sessions?page=1&limit=10`, {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
        },
    });

    check(getSessionsResponse, {
        'get sessions successful': (r) => r.status === 200,
    });

    sleep(0.5);
}
