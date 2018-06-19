/* shopify-also-bot
*  verion:
*  about:
*  date:
*  author: don hagell
*  reference: https://help.shopify.com/api/tutorials/building-node-app
*/
//const dotenv = require('dotenv').config();
const path = require('path');
const dotenv = require('dotenv').config({path: path.join('D:\\Apps\\shopify-also-bot\\', '.env.alsobot')});

const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'read_products';
const forwardingAddress = process.env.SHOPIFY_APP_HOST; // Replace this with your HTTPS Forwarding address

app.get('/', (req, res) => {
  res.send(req.query.ids);
});

app.listen(8082, () => {
  console.log('Example app listening on port 8082!');
});

app.get('/alsobot', (req, res) => {
  const shop = req.query.shop;
  const ids = req.query.ids;
  console.log(req.query,ids);
  if (shop) {
    const state = nonce();
    const redirectUri = forwardingAddress + '/alsobot/callback' ;
    const installUrl = 'https://' + shop +
      '/admin/oauth/authorize?client_id=' + apiKey +
      '&scope=' + scopes +
      '&state=' + state +
      '&ids=' + ids +
      '&redirect_uri=' + redirectUri;


	res.setHeader('Set-Cookie', cookie.serialize('ids', String(ids), {
      httpOnly: true,
      maxAge: 60 * 60 * 24 * 7 // 1 week
    }));
    res.cookie('state', state);
    res.cookie('ptoke', state);
    //res.cookie('ids', ids);
	res.redirect(installUrl);
  } else {
    return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
  }
});

app.get('/alsobot/callback', (req, res) => {
  const { shop, hmac, code, state, ids } = req.query;
  const stateCookie = cookie.parse(req.headers.cookie).state;
  const idsCookie = cookie.parse(req.headers.cookie).ids;
  const ptokeCookie = cookie.parse(req.headers.cookie).ptoke;
  console.log(req.query,req.params,ptokeCookie,idsCookie);
  if (state !== stateCookie) {
    return res.status(403).send('Request origin cannot be verified');
  }
  // STEP 1 - Validate HMAC Request
  if (shop && hmac && code) {
	// Your app needs to validate the request by using HMAC validation to make sure that the request has come from Shopify. 
	// To validate the request, replace res.status(200).send('Callback route');
    //res.status(200).send('Callback route');
	const map = Object.assign({}, req.query);
	delete map['signature'];
	delete map['hmac'];
	const message = querystring.stringify(map);
	const providedHmac = Buffer.from(hmac, 'utf-8');
	const generatedHash = Buffer.from(
	  crypto
		.createHmac('sha256', apiSecret)
		.update(message)
		.digest('hex'),
		'utf-8'
	  );
	let hashEquals = false;
	// timingSafeEqual will prevent any timing attacks. Arguments must be buffers
	try {
	  hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
	// timingSafeEqual will return an error if the input buffers are not the same length.
	} catch (e) {
	  hashEquals = false;
	};

	if (!hashEquals) {
	  return res.status(400).send('HMAC validation failed');
	}
	// STEP 2 - Exchange Code for Access Token
	// To exchange the provided code parameter for a permanent access_token, replace res.status(200).send('HMAC validated');
	//res.status(200).send('HMAC validated');
	const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
	const accessTokenPayload = {
	  client_id: apiKey,
	  client_secret: apiSecret,
	  code,
	};
	request.post(accessTokenRequestUrl, { json: accessTokenPayload })
	.then((accessTokenResponse) => {
		const accessToken = accessTokenResponse.access_token;
		// STEP 3
		// To use the access token to make an API call to the shop endpoint, replace res.status(200).send("Got an access token, let's do something with it");
		// res.status(200).send("Got an access token, let's do something with it");
		// Use access token to make API call to 'shop' endpoint
		const shopRequestUrl = 'https://' + shop + '/admin/products.json?fields=id,title,variants&ids='+idsCookie;
		const shopRequestHeaders = {
		  'X-Shopify-Access-Token': accessToken,
		};
		console.log(shopRequestUrl);
		request.get(shopRequestUrl, { headers: shopRequestHeaders })
		.then((shopResponse) => {
		  res.cookie('ptoke', accessToken);
		  items = JSON.parse(shopResponse);
		  console.log(items.products);
		  res.send(shopResponse);
		})
		.catch((error) => {
		  res.status(error.statusCode).send(error.error_description);
		});
	})
	.catch((error) => {
	  res.status(error.statusCode).send(error.error.error_description);
	});
	/*
	*
	*/
	const metaFieldRequestUrl = 'https://' + shop + '/admin/metafields.json';
	const metaFieldPayload = {
			"metafield": {
			"namespace": "product",
			"key": "transitions",
			"value": 25,
			"value_type": "integer"
		  }
		};
	const shopRequestHeaders = {
		  'X-Shopify-Access-Token': ptokeCookie,
		};
	console.log(metaFieldRequestUrl);
	request.post(metaFieldRequestUrl, { headers: shopRequestHeaders, json: metaFieldPayload })
	.then((metaFieldResponse) => {
		const accessToken = ptokeCookie;
		// STEP 3.1
		// To use the access token to make an API call to the shop endpoint, replace res.status(200).send("Got an access token, let's do something with it");
		// res.status(200).send("Got an access token, let's do something with it");
		// Use access token to make API call to 'shop' endpoint
		const shopRequestUrl = 'https://' + shop + '/admin/metafields.json';
		const shopRequestHeaders = {
		  'X-Shopify-Access-Token': accessToken,
		};
		console.log(shopRequestUrl);
		request.get(shopRequestUrl, { headers: shopRequestHeaders })
		.then((shopResponse) => {
		  res.cookie('ptoke', accessToken);
		  items = JSON.parse(shopResponse);
		  console.log(items.products);
		  res.send(shopResponse);
		})
		.catch((error) => {
		  res.status(error.statusCode).send(error.error.error_description);
		});
	})
	.catch((error) => {
	  res.status(error.statusCode).send(error.error.error_description);
	});	
	
	
	
  } else {
    res.status(400).send('Required parameters missing');
  }
});
const getRawBody = require('raw-body');

 function withWebhook({ secret, shopStore }) {
    return function withWebhook(request, response, next) {
        const { body: data } = request;
        const hmac = request.get('X-Shopify-Hmac-Sha256');
        const topic = request.get('X-Shopify-Topic');
        const shopDomain = request.get('X-Shopify-Shop-Domain');

        try {
            getRawBody(request)
                .then(buffer => {
                    const generated_hash = crypto
                        .createHmac('sha256', secret)
                        .update(buffer)
                        .digest('base64');

                    if (generated_hash !== hmac) {
                        response.status(401).send();
                        throw new Error("Unable to verify request HMAC");
                        return;
                    }

                    shopStore.getShop({ shop: shopDomain }, (error, { accessToken }) => {
                        if (error) {
                            response.status(401).send();
                            throw new Error("Couldn't fetch credentials for shop");
                            return;
                        }

                        request.body = buffer.toString('utf8');
                        request.webhook = { topic, shopDomain, accessToken };

                        next();
                    });
                })
                .catch(err => {
                    console.log(err);
                });
        } catch(error) {
            response.send(error);
        }
    };
};

app.post('/order-create', withWebhook((error, request) => {
  if (error) {
    console.error(error);
    return;
  }

  console.log('We got a webhook!');
  console.log('Details: ', request.webhook);
  console.log('Body:', request.body);
}));
