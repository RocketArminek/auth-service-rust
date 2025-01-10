// tests/performance/scenarios/spike_test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
    stages: [
        { duration: '1m', target: 10 },    // Baseline load
        { duration: '30s', target: 100 },  // Spike to 100 users
        { duration: '30s', target: 10 },   // Scale down to baseline
        { duration: '1m', target: 100 },   // Stay at 100 users
        { duration: '1m', target: 100 },   // Stay at 100 users
        { duration: '1m', target: 10 },    // Verify baseline performance
    ],
    thresholds: {
        http_req_failed: ['rate<0.01'],
        checks: ['rate>0.99'],
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
        path: '/v1/stateless/login',
        body: () => ({
            email: 'admin@example.com',
            password: 'Admin#123*',
        }),
    },
    // Add more endpoints as needed
];

export default function () {
    // Randomly select an endpoint
    const endpoint = ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)];

    const response = http.post(
        `${BASE_URL}${endpoint.path}`,
        JSON.stringify(endpoint.body()),
        {
            headers: { 'Content-Type': 'application/json' },
        }
    );

    // Check response and record metrics
    check(response, {
        'status is 200 or 201': (r) => [200, 201].includes(r.status),
    });

    if (response.status >= 400) {
        errorRate.add(1);
    }

    sleep(0.3);
}
