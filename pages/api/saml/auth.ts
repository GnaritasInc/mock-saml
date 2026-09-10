import { createHash, timingSafeEqual } from 'crypto';
import config from 'lib/env';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { User } from 'types';
import saml from '@boxyhq/saml20';
import { getEntityId } from 'lib/entity-id';

function passwordsMatch(provided: unknown, expected: string): boolean {
  if (typeof provided !== 'string' || !expected) {
    return false;
  }

  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(expected);
  const length = Math.max(providedBuf.length, expectedBuf.length, 1);
  const paddedProvided = Buffer.alloc(length);
  const paddedExpected = Buffer.alloc(length);

  providedBuf.copy(paddedProvided);
  expectedBuf.copy(paddedExpected);

  return timingSafeEqual(paddedProvided, paddedExpected) && providedBuf.length === expectedBuf.length;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { email, audience, acsUrl, id, relayState, password } = req.body;

    console.log("In auth handler")
    console.log('audience', audience);
    console.log('email', email);

    const loginPassword = process.env.LOGIN_PASSWORD || '';

    if (!loginPassword) {
      res.status(500).send('LOGIN_PASSWORD is not configured');
      return;
    }

    if (!passwordsMatch(password, loginPassword)) {
      res.status(401).send('Invalid password');
      return;
    }


    // if (!email.endsWith('@example.com') && !email.endsWith('@example.org')) {
    //   res.status(403).send(`${email} denied access`);
    // }

    const userId = createHash('sha256').update(email).digest('hex');
    const userName = email.split('@')[0];

    const user: User = {
      id: userId,
      email,
      firstName: userName,
      lastName: userName,
    };

    console.log("Creating signed SAML response", config.entityId, req.query.namespace as any)
    const xmlSigned = await saml.createSAMLResponse({
      issuer: getEntityId(config.entityId, req.query.namespace as any),
      audience,
      acsUrl,
      requestId: id,
      claims: {
        email: user.email,
        raw: user,
      },
      privateKey: config.privateKey,
      publicKey: config.publicKey,
    });
    console.log("Got signed SAML response")

    const encodedSamlResponse = Buffer.from(xmlSigned).toString('base64');
    const html = saml.createPostForm(acsUrl, [
      {
        name: 'RelayState',
        value: relayState,
      },
      {
        name: 'SAMLResponse',
        value: encodedSamlResponse,
      },
    ]);

    // console.log("Sending SAML response", html)

    res.send(html);
  } else {
    res.status(405).send(`Method ${req.method} Not Allowed`);
  }
}
