import React from 'react'
import {act, fireEvent, render} from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import  Signup from './Signup';
import SdkService from '../utils/sdkService';
import userEvent from '@testing-library/user-event';

window.alert = jest.fn()

describe('Test Signup component', () => {
    test('Form render without email params', () => {
        const { queryByText, queryByRole, queryByLabelText, container } = render(
            <MemoryRouter>
                <Signup />
            </MemoryRouter>
        );
        
        expect(queryByText('Create account')).toBeTruthy();
        expect(queryByText('Welcome to your personal wallet. Here you will be able to store, view and manage your digital identity.', { exact: false })).toBeTruthy();
        expect(queryByText('In order to access your wallet you will need to set up a password first', { exact: false })).toBeTruthy();
        expect(queryByLabelText('Username')).toBeTruthy();
        expect(queryByLabelText('Password')).toBeTruthy();
        expect(queryByLabelText('Confirm Password')).toBeTruthy();
        expect(queryByRole('checkbox', {name: 'I accept the terms and conditions'})).toBeTruthy();
        expect(queryByRole('button', {name: 'Sign Up'})).toBeTruthy();
        expect(container.querySelector('[href="/login"]')).toBeTruthy();
    });

    test('Form render with email params', () => {
        jest.spyOn(URLSearchParams.prototype, 'get').mockImplementation(x=>'test@mail.com');
        const { queryByText, queryByRole, queryByLabelText, container } = render(
            <MemoryRouter>
                <Signup />
            </MemoryRouter>
        );
        
        expect(queryByText('Create account')).toBeTruthy();
        expect(queryByText('Welcome to your personal wallet. Here you will be able to store, view and manage your digital identity.', { exact: false })).toBeTruthy();
        expect(queryByText('In order to access your wallet you will need to set up a password first', { exact: false })).toBeTruthy();
        expect(queryByLabelText('Username')).not.toBeTruthy()
        expect(queryByLabelText('Password')).toBeTruthy();
        expect(queryByLabelText('Confirm Password')).toBeTruthy();
        expect(queryByRole('checkbox', {name: 'I accept the terms and conditions'})).toBeTruthy();
        expect(queryByRole('button', {name: 'Sign Up'})).toBeTruthy();
        expect(container.querySelector('[href="/login"]')).toBeTruthy();

    });

    describe('User Signup Functionality', () => {
        test('User can sign up with correct data and route to /', async () => {
            const history = { push: jest.fn() };
            const { getByRole, getByLabelText } = render(
                <MemoryRouter>
                    <Signup history={history} />
                </MemoryRouter>
            );

            const correctData = {
                username: 'test',
                password: 'testtesttest',
            }

            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const cfmPasswordField = getByLabelText('Confirm Password');
            const termsCheckBox = getByRole('checkbox', {name: 'I accept the terms and conditions'});
            const submitButton = getByRole('button', {name: 'Sign Up'});

            window.sdk = new SdkService()
            jest.spyOn(SdkService.prototype, 'signUp').mockImplementation((username, password) => 'testToken')
            
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: correctData.username
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: correctData.password
                    }
                });

                fireEvent.change(cfmPasswordField, {
                    target: {
                        value: correctData.password
                    }
                });

                userEvent.click(termsCheckBox);
            })
            await act(async () => await userEvent.click(submitButton));

            expect(SdkService.prototype.signUp).toBeCalledWith(correctData.username, correctData.password);
            expect(history.push).toBeCalledWith('/', {"username": correctData.username})
        });

        test('User receieve an alert if password and confirm password fields does not match', async () => {
            const history = { push: jest.fn() };
            const { getByRole, getByLabelText } = render(
                <MemoryRouter>
                    <Signup history={history} />
                </MemoryRouter>
            );

            const correctData = {
                username: 'test',
                password: 'testtesttest',
            }

            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const cfmPasswordField = getByLabelText('Confirm Password');
            const termsCheckBox = getByRole('checkbox', {name: 'I accept the terms and conditions'});
            const submitButton = getByRole('button', {name: 'Sign Up'});

            window.sdk = new SdkService()
            jest.spyOn(SdkService.prototype, 'signUp').mockImplementation()
            
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: correctData.username
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: correctData.password
                    }
                });

                fireEvent.change(cfmPasswordField, {
                    target: {
                        value: 'wrong password'
                    }
                });

                userEvent.click(termsCheckBox);
            })

            await act(async () => await userEvent.click(submitButton));

            expect(window.alert).toBeCalledWith('Passwords don\'t match!');
        });

        test("Signup button disabled if form is invalid", async () => {
            const history = { push: jest.fn() };
            const { getByRole, getByLabelText } = render(
                <MemoryRouter>
                    <Signup history={history} />
                </MemoryRouter>
            );

            const correctData = {
                username: '',
                password: '',
            }

            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const cfmPasswordField = getByLabelText('Confirm Password');
            const submitButton = getByRole('button', {name: 'Sign Up'});

            window.sdk = new SdkService()
            jest.spyOn(SdkService.prototype, 'signUp').mockImplementation()
            
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: correctData.username
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: correctData.password
                    }
                });

                fireEvent.change(cfmPasswordField, {
                    target: {
                        value: 'wrong password'
                    }
                });

            })
            expect(submitButton).toBeDisabled()
        })

        test('alert will show if there is an error when using sdkService', async () => {
            const history = { push: jest.fn() };
            const { getByRole, getByLabelText } = render(
                <MemoryRouter>
                    <Signup history={history} />
                </MemoryRouter>
            );

            const correctData = {
                username: 'test',
                password: 'testtesttest',
            }

            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const cfmPasswordField = getByLabelText('Confirm Password');
            const termsCheckBox = getByRole('checkbox', {name: 'I accept the terms and conditions'});
            const submitButton = getByRole('button', {name: 'Sign Up'});

            window.sdk = new SdkService()
            const error = new Error('This is a test');
            jest.spyOn(SdkService.prototype, 'signUp').mockImplementation((username, password) => {
                throw error
            })
            
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: correctData.username
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: correctData.password
                    }
                });

                fireEvent.change(cfmPasswordField, {
                    target: {
                        value: correctData.password
                    }
                });

                userEvent.click(termsCheckBox);
            })

            await act(async () => await userEvent.click(submitButton));

            expect(window.alert).toBeCalledWith(error.message);
        })
    })
});