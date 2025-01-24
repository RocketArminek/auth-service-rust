import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
    cloud: {
        projectID: 3737499,
    },
    stages: [
        { duration: '1m', target: 10 },
        { duration: '30s', target: 100 },
        { duration: '30s', target: 10 },
        { duration: '1m', target: 100 },
        { duration: '1m', target: 100 },
        { duration: '1m', target: 10 },
    ],
    thresholds: {
        http_req_failed: ['rate==0.0'],
        checks: ['rate==1.0'],
        http_req_duration: ['p(95)<20', 'avg<10', 'max<300'],
        errors: ['rate<0.01'],
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

const ENDPOINTS = [
    {
        method: 'POST',
        path: '/v1/users',
        body: () => ({
            email: `spike_${Date.now()}_${Math.random()}@example.com`,
            password: 'Test#pass123',
            role: 'USER',
        }),
    },
    {
        method: 'POST',
        path: '/v1/login',
        body: () => ({
            email: 'admin@example.com',
            password: 'Admin#123*',
        }),
    },
];

export default function () {
    const endpoint = ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)];

    const response = http.post(
        `${BASE_URL}${endpoint.path}`,
        JSON.stringify(endpoint.body()),
        {
            headers: { 'Content-Type': 'application/json' },
        }
    );

    check(response, {
        'status is 200 or 201': (r) => [200, 201].includes(r.status),
    });

    if (response.status >= 400) {
        errorRate.add(1);
    }

    sleep(0.3);
}
