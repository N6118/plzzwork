import React, { FC, useState } from "react";
import { useAuthentication } from "./Authentication";
import { Button, Form, FormControl } from "react-bootstrap";
import { signup } from '../services/apiService';

interface IProps {
  children?: React.ReactNode
  setShowSignUp: any
}
const Signup: FC<IProps> = ({ setShowSignUp }) => {
  const { loading } = useAuthentication();
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [isCheckboxChecked, setCheckboxChecked] = useState<boolean>(false);

  async function handleSignup() {
    if (!isCheckboxChecked) {
      return alert('Please agree with the terms and conditions before you sign up.')
    }

    if (password !== confirmPassword) {
      return alert('Passwords do not match.')
    }

    try {
      const token = await signup(username, password);

      if (token){
        alert('Account has been created. Please sign in.');
        setShowSignUp(false);
      }
    } catch (err) {
      alert(err.message);
    }
  }

  return (
    <div className='Login'>
      <div className='Form'>
        <h1 className='Title'>Verifier Sign Up</h1>
        <p className='Info'>
          Sign up as a Verifier to request and receive credentials for transactions!
        </p>

        <Form style={{ width: 280 }}>
          <Form.Group controlId="username">
            <Form.Label>Username</Form.Label>
            <FormControl
              autoFocus
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Form.Group>

          <Form.Group controlId="password">
            <Form.Label>Password</Form.Label>
            <FormControl
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </Form.Group>

          <Form.Group controlId="confirmpassword">
            <Form.Label>Confirm Password</Form.Label>
            <FormControl
              type="password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
            />
          </Form.Group>

          <Form.Group controlId='checkbox'>
            <Form.Check
                className='Signup-Checkbox'
                type='checkbox'
                checked={isCheckboxChecked}
                onChange={() => setCheckboxChecked(true)}
                label='I accept the terms and conditions'
            />
          </Form.Group>

          <Button block disabled={loading} onClick={handleSignup}>
            Sign Up
          </Button>
        </Form>
      </div>
    </div>
    
  );
};

export default Signup;
