# Affinidi Use Case Implementation - Driving License - Issuer
[![Generic badge](https://img.shields.io/badge/Test_Coverage-95%-<COLOR>.svg)](https://shields.io/)

## Table of contents

- [Introduction](#introduction)
- [Initial Set Up](#how-to-setup)

  - [Generate Affinidi API Key](#generate-api-key)
  - [Amazon SES Credentials](#amazon-ses)
  - [Firebase Credentials](#firebase)
  - [Configure .env File](#configure-.env-file)

- [How to run](#how-to-run)
  - [Sequence](#sequence)

## Introduction

Welcome to Driving License Use Case - Issuer application. In this application, you will experience how does a normal applicant would like to sign up for a verifiable credential and thereafter how a Issuer checks the information and issues a verifiable credential to the applicant.

You can either run this program in your local machine or try it out here: https://usecases.drivinglicense-issuer.vc-generator.com/

## Initial Set Up

### Generate API Key

Before you could use our API and SDK services, you would have to register to get the API keys.

1. Go to apikey.affinidi.com
2. Register for an account
3. Store the `API Key` and `API Key Hash` safely


### EmailJS 

In case you want to use EmailJS for smtp please follow these steps.
1. Register on EmailJS
2. Create a service
3. Create an template with the following structure
![Alt text](public/emailjs.PNG?raw=true "Title")
4. Save the Service ID, Template ID and User ID in the `.env` file.
5. You can find the User ID in the Integration menu.


### Firebase

Note: This step will be optional.

In our issuer application, we will be using firebase to mimic issuer's database which stores all of the applications.

1. Go to Firebase Console https://console.firebase.google.com/
2. Create a new Firestore
3. Navigation to Project Settings
4. Look for `firebaseConfig` and copy the credentials. It should look like

```
  var firebaseConfig = {
    apiKey: <<SOME API KEY>>,
    authDomain: "<<SOMEP PROJECT NAME>>.firebaseapp.com",
    projectId: "<<SOMEP PROJECT NAME>>",
    storageBucket: "<<SOMEP PROJECT NAME>>.appspot.com",
    messagingSenderId: <<SOME STRING>>,
    appId: <<SOME STRING>>
  };
```

### Configure .env file

1. Open terminal and navigate to the project folder
2. Run `cp .env.example .env`
3. Fill in the .env file with the details that you have gathered in the previous steps

```
REACT_APP_API_KEY=<<Afffinidi's API Key>>
REACT_APP_API_KEY_HASH=<<Affinidi's API Key Hash>>
REACT_APP_ENVIRONMENT=prod
REACT_APP_WALLET_URL=<<URL OF THE WALLET APPLICATION>>

REACT_APP_FIREBASE_API_KEY=<<Firebase's apiKey>>
REACT_APP_FIREBASE_AUTHDOMAIN=<<Firebase's authDomain>>
REACT_APP_FIREBASE_PROJECT_ID=<<Firebase's projectId>>
REACT_APP_FIREBASE_STORAGEBUCKET=<<Firebase's storageBucket>>
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=<<Firebase's messagingSenderId>>
REACT_APP_FIREBASE_APP_ID=<<Firebase's appId>>

REACT_APP_EMAIL_JS_SERVICE_ID=<<EmailJs service ID>>
REACT_APP_EMAIL_JS_TEMPLATE_ID=<<EmailJs template ID>>
REACT_APP_EMAIL_JS_USER_ID=<<EmailJs user ID>>
```

## How to run

1. Open terminal and navigate to the project folder
2. Run `npm install`
3. Run `cp .env.example .env`
4. Populate the credentials in `.env`
5. Run `npm start`

### Sequence

Run Issuer, Holder and Verifier in this sequence in your local machine.
