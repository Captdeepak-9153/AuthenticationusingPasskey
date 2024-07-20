const express = require('express');
const { generateRegistrationOptions , verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const crypto = require('node:crypto');

if(!globalThis.crypto) {
  globalThis.crypto = crypto;
}



const app = express();
const port = 3000;

// Middleware
app.use(express.static('./public'));
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  res.send('Hello, Express!');
});

// States
const userStore = {};
const challengestore= {};
const loginstore={};


app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const id = `user_${Date.now()}`;

  const user = {
    id,
    username,
    password
  };
  userStore[id] = user;

  console.log('Register successful', userStore[id]);

  return res.json({ id }); // it will send id to the url as a parameter
});

app.post('/register-challenge' , async (req,res)=>{
    const {userId} = req.body; // it will give the unique usserid

    if (!userStore[userId]) return res.status(404).json({error:'User not found'}); // checking user is exits or not

    const user = userStore[userId]


    const challengePayload = await generateRegistrationOptions({   
        rpID:'localhost',  //it tells about domain name of the frontend hosted
        rpName:"my localhost machine",
        userName: user.username // username come from user store
    })

    challengestore[userId] = challengePayload.challenge // it will store challenge in a variable called 'challenge' which we have defined above as an empty object {} and then we are assigning the value of the challenge to this;
     return res.json({ options : challengePayload  }) // it will send that challenge to challengepayload to frontend
});

app.post('/register-verify' , async (req,res)=>{
  const {userId , cred} = req.body;
  
  
  if (!userStore[userId]) return res.status(404).json({error:'User not found'}); // checking user is exits or not

  const user = userStore[userId]
  const challenge = challengestore[userId]

  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge:challenge,
    expectedOrigin: 'http://localhost:3000',
    expectedRPID:'localhost',
    response:cred // cred is the resposne sent from the frontend
   })

   if(!verificationResult.verified) return res.json({error :'Verification failed'});
   userStore[userId].passkey = verificationResult.registrationInfo // it will store passkey in the backend

   return res.json({verified:true}) // it will send a message that fronend passkey and backend passkey are matched and verified
});

app.post('/login-challenge' , async (req,res)=>{
  const{userId} = req.body;
  
  if (!userStore[userId]) return res.status(404).json({error:'User not found'}); // checking user is exits or not

  const opts = await generateAuthenticationOptions({
    rpID:'localhost'
  })
  loginstore[userId] = opts.challenge;
  return res.json({ options : opts });

});

app.post('/login-verify' , async(req,res)=>{
  const {userId , cred} = req.body;

  if (!userStore[userId]) return res.status(404).json({error:'User not found'}); // checking user is exits or not
  const user = userStore[userId]
  const challenge = loginstore[userId]

  const Result = await verifyAuthenticationResponse({
    expectedChallenge:challenge,
    expectedOrigin: 'http://localhost:3000',
    expectedRPID:'localhost',
    response:cred, // cred is the resposne sent from the frontend
    authenticator: user.passkey
   })

   if(!Result.verified) return res.json({error:'Verification failed'}) // it will send a message that fronend passkey and backend passkey are matched and verified
   
   //login the user:Session , cookies, JWT
   
   return res.json({success: true , userId})



  })

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is hosted at http://localhost:${port}`);
});