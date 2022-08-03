import { Axios, AxiosRequestConfig } from 'axios';
import { createHash, createSign } from 'crypto';

export type SigningHttpConfig = {
    keyId: string,
    privKey: Buffer | string,
    headers?: Array<string>
};

export class HttpSigning {
    config: SigningHttpConfig;

    constructor(config: SigningHttpConfig) {
        this.config = config;
    }

    onFulfilled() {
        return (config: AxiosRequestConfig) => {
            const hash = createHash('sha256');

            const date = (new Date()).toISOString();

            let digest: string | null = null;

            if (config.data) {
                digest = 'SHA-256=' + Buffer.from(hash.update(JSON.stringify(config.data))
                    .digest('binary'), 'binary')
                    .toString('base64');
            }
            if (this.config.headers === undefined) {
                this.config.headers = ['date'];
            }

            const headers = this.config.headers.join(' ');

            if (config.headers === undefined) {
                config.headers = {
                    date: date,
                };
            }

            const message = this.config.headers.map(item => {
                let value = config.headers?.hasOwnProperty(item) ? config.headers[item] : null;

                if (item === '(request-target)') {
                    value = config.method?.toLowerCase() + ' ' + (new URL(config.url as string)).pathname;
                } else if (item.toLowerCase() === 'date') {
                    value = date;
                } else if (item.toLowerCase() === 'digest') {
                    value = digest;
                }

                return item + ': ' + value;
            }).join('\n');

            const sign = createSign('RSA-SHA256');

            sign.write(message);
            sign.end();

            const signature = Buffer.from(sign.sign(this.config.privKey)).toString('base64');

            config.headers.date = date;
            config.headers.authorization = 'Signature keyId="' + this.config.keyId +
                '",algorithm="rsa-sha256",headers="' + headers + '",signature="' + signature + '"';
            if (digest !== null) {
                config.headers.digest = digest;
            }
            return config;
        };
    }
}

export const authorizeWithDigest = (client: Axios, config: SigningHttpConfig) => {
    const httpSigning = new HttpSigning(config);

    client.interceptors.request.use(httpSigning.onFulfilled());

    return client;
};

export default authorizeWithDigest;
