/* eslint-disable jsx-a11y/anchor-is-valid */
import React, { useState } from 'react';
import ApplicantSignup from 'components/user/applicant/signup/Signup';
import ApplicantLogin from 'components/user/applicant/login/Login';

const signUpSubComponent = (
    <>
      <h1 className='title'>Create Issuer Account</h1>
      <ApplicantSignup/>
    </>
)

const logInSubComponent = (
    <>
      <h1 className='title'>Applicant Login</h1>
      {/* <p>Please log in using Affindi Wallet's credentials.</p> */}
      <ApplicantLogin/>
    </>
)

const ApplicantLoginPage: React.FC = (): React.ReactElement => {
    // Toggle to which between Login or Sign up component
    const [showSignUp, setShowSignUp] = useState<boolean>(false)

    return (
        <div className='page-form page-form--slim'>
            { showSignUp ? signUpSubComponent : logInSubComponent }
            { showSignUp ? <small>Already have registered the project?<a href='#' onClick={() => setShowSignUp(false)}> Log in here </a></small>: <small>Don't have an Issuer account?<a href='#' onClick={() => setShowSignUp(true)}> Sign up here </a></small>}
        </div>
    )
}

export default ApplicantLoginPage