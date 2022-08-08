import axios, { AxiosResponse } from 'axios';
import authorizeWithDigest from '../index';
import * as fs from 'fs';
import nock from 'nock';

describe('http signing', () => {
    test('check auth', async () => {
        const client = axios.create();
        const host = 'https://fake.url';

        nock(host)
            .post('/api/shaq/FAKE')
            .reply(200, function (uri, requestBody) {
                const check = this.req.headers.authorization.split(',');

                expect(check[0]).toStrictEqual('Signature keyId="DEMO.myApp"');
                expect(check[1]).toStrictEqual('algorithm="rsa-sha256"');
                expect(check[2]).toStrictEqual('headers="(request-target) date digest"');
                expect(uri).toStrictEqual('/api/shaq/FAKE');
                expect(requestBody).toStrictEqual({
                    test: 'ok',
                });
            });

        authorizeWithDigest(client, {
            keyId: 'DEMO.myApp',
            privKey: fs.readFileSync(__dirname + '/../rsa.private'),
            headers: [
                '(request-target)',
                'date',
                'digest',
            ],
        });

        const response: AxiosResponse = await client.post(host + '/api/shaq/FAKE',
            {
                test: 'ok',
            },
            {
                headers: {
                    'signing-auth': 'ok',
                },
            });

        expect(response.status).toStrictEqual(200);
    });

    test('check auth with no headers', async () => {
        const client = axios.create();
        const host = 'https://fake.url';

        nock(host)
            .post('/api/shaq/FAKE')
            .reply(200, function (uri, requestBody) {
                const check = this.req.headers.authorization.split(',');

                expect(check[0]).toStrictEqual('Signature keyId="DEMO.myApp"');
                expect(check[1]).toStrictEqual('algorithm="rsa-sha256"');
                expect(check[2]).toStrictEqual('headers="date"');
                expect(uri).toStrictEqual('/api/shaq/FAKE');
                expect(requestBody).toStrictEqual({
                    test: 'ok',
                });
            });

        authorizeWithDigest(client, {
            keyId: 'DEMO.myApp',
            privKey: fs.readFileSync(__dirname + '/../rsa.private'),
        });

        const response: AxiosResponse = await client.post(host + '/api/shaq/FAKE',
            {
                test: 'ok',
            },
            {
                headers: {
                    'signing-auth': 'ok',
                },
            });

        expect(response.status).toStrictEqual(200);
    });
});
