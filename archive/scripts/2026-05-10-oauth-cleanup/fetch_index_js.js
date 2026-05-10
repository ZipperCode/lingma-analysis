// Fetch the index.js file and save it locally
const https = require('https');
const fs = require('fs');

const url = 'https://lingma.alibabacloud.com/static/yunxiao-fe/cosy-client-assets/0.1.12/index.js';
const outputPath = 'D:\\Project\\lingma\\cosy_client_index.js';

https.get(url, { rejectUnauthorized: false }, (res) => {
  if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
    console.log('Redirect to:', res.headers.location);
    https.get(res.headers.location, { rejectUnauthorized: false }, (res2) => {
      let data = '';
      res2.on('data', chunk => data += chunk);
      res2.on('end', () => {
        fs.writeFileSync(outputPath, data);
        console.log(`Downloaded ${data.length} bytes to ${outputPath}`);
      });
    });
  } else {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      fs.writeFileSync(outputPath, data);
      console.log(`Downloaded ${data.length} bytes to ${outputPath}`);
    });
  }
}).on('error', err => {
  console.error('Error:', err.message);
});
