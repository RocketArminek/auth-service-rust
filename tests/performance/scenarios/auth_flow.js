import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
    stages: [
        { duration: '1m', target: 50 },
        { duration: '3m', target: 50 },
        { duration: '1m', target: 0 },
    ],
    thresholds: {
        http_req_failed: ['rate<0.01'],
        checks: ['rate>0.99'],
        http_req_duration: ['p(95)<20', 'avg<10', 'max<300'],
        errors: ['rate<0.01'],
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export function setup() {
    const email = `perf_test_${Date.now()}@example.com`;
    const password = 'Test#password123';

    const createUserResponse = http.post(`${BASE_URL}/v1/users`, JSON.stringify({
        email: email,
        password: password,
        role: 'USER'
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(createUserResponse, {
        'user created successfully': (r) => r.status === 201,
    });

    return { email, password };
}

export default function (data) {
    const loginResponse = http.post(`${BASE_URL}/v1/stateless/login`, JSON.stringify({
        email: data.email,
        password: data.password
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(loginResponse, {
        'login successful': (r) => r.status === 200,
    });

    if (loginResponse.status === 200) {
        const body = JSON.parse(loginResponse.body);
        const accessToken = body.accessToken.value;

        // Test authenticated endpoints
        const authenticateResponse = http.get(`${BASE_URL}/v1/stateless/authenticate`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        });

        check(authenticateResponse, {
            'authentication successful': (r) => r.status === 200,
        });

        // Update profile
        const updateResponse = http.put(`${BASE_URL}/v1/me`, JSON.stringify({
            firstName: 'Test',
            lastName: 'User',
            avatarPath: null
        }), {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });

        check(updateResponse, {
            'profile update successful': (r) => r.status === 200,
        });

        const refreshResponse = http.post(`${BASE_URL}/v1/stateless/refresh`, null, {
            headers: {
                'Authorization': `Bearer ${body.refreshToken.value}`,
            },
        });

        check(refreshResponse, {
            'token refresh successful': (r) => r.status === 200,
        });
    }

    sleep(1);
}

export function teardown(data) {
    // Cleanup test data if needed
}
