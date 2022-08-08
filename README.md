# Axios plugin: HTTP signing

This library permit to sign with axios and private rsa key

```typescript
import authorizeWithDigest from '@redspher/axios-http-signing';
import axios from 'axios';

const client = axios.create();

authorizeWithDigest(client, {
    keyId: 'DEMO.myApp',
    privKey: '{the private key: put the content of a rsa private key in pem format}',
    headers: [
        '(request-target)',
        'date',
        'digest',
    ],
});

// Now when you use the client, it will add the headers to sign to api
client.post('https://fakeurl/api', { toto: 'toto' }, {
        headers: {
            'signing-auth': 'ok',
        },
    })
    .then(console.log)
    .catch(console.error);
```
