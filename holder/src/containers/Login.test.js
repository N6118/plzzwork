import React from 'react'
import {act, fireEvent, render} from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Login from './Login';
import SdkService from '../utils/sdkService';
import userEvent from '@testing-library/user-event';



describe('Test Login component', () => {
    test('Form render', () => {
        const { getByText, getByRole, getByLabelText, container } = render(
            <MemoryRouter>
                <Login />
            </MemoryRouter>
        );

        expect(getByText('Holder Login')).toBeTruthy();
        expect(getByText('Login in order to continue')).toBeTruthy();
        expect(getByLabelText('Username')).toBeTruthy();
        expect(getByLabelText('Password')).toBeTruthy();
        expect(container.querySelector('[href="/reset-password"]')).toBeTruthy();
        expect(getByRole('button', {name: 'Login'})).toBeTruthy();
    });

    describe('User Login Functionality', () => {

        beforeEach(()=>{
            window.sdk = new SdkService();
            jest.spyOn(SdkService.prototype, 'fromLoginAndPassword').mockImplementation((username, password) => true);
            jest.spyOn(console, 'log').mockImplementation();
        });
        
        test('login and route to accept page', async () => {
            const history = {
                push: jest.fn()
            };
            const testLoginProps = {
                isAuthenticated: false,
                userHasAuthenticated: jest.fn(x=>{}),
                setShareRequestToken: jest.fn(x=>{}),
                setAcceptVCLink: null,
            };
            window.alert = jest.fn((x)=>{})

            const { getByLabelText, getByRole } =render(
                <MemoryRouter>
                    <Login 
                        isAuthenticated={testLoginProps.isAuthenticated}
                        userHasAuthenticated={testLoginProps.userHasAuthenticated}
                        shareRequestToken={'shareRequestToken'}
                        setShareRequestToken={testLoginProps.setShareRequestToken}
                        acceptVCLink={'acceptVCLink'}
                        setAcceptVCLink={testLoginProps.setAcceptVCLink}
                        history = {history}
                    />
                </MemoryRouter>
            )
    
            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const submitButton = getByRole('button', {name: 'Login'});
    
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: 'test'
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: 'test'
                    }
                });
            })
    
    
            await act(async () => {
                await userEvent.click(submitButton);
            })
            expect(SdkService.prototype.fromLoginAndPassword).toBeCalledWith('test', 'test');
            expect(testLoginProps.userHasAuthenticated).toBeCalledWith(true);
            expect(console.log).toBeCalledWith('routing to accept page');
            expect(history.push).toBeCalledWith(`/accept-credentials?vcURL=${'acceptVCLink'}`);
            expect(console.log).not.toBeCalledWith('routing to share page');
            expect(history.push).not.toBeCalledWith(`/share-credentials?token=${'shareRequestToken'}`);
            expect(history.push).not.toBeCalledWith('/', 'test');
        });

        test('login and route to share page', async () => {
            const history = {
                push: jest.fn()
            };
            const testLoginProps = {
                isAuthenticated: false,
                userHasAuthenticated: jest.fn(x=>{}),
                setShareRequestToken: jest.fn(x=>{}),
                setAcceptVCLink: null,
            };
            window.alert = jest.fn((x)=>{})

            const { getByLabelText, getByRole } =render(
                <MemoryRouter>
                    <Login 
                        isAuthenticated={testLoginProps.isAuthenticated}
                        userHasAuthenticated={testLoginProps.userHasAuthenticated}
                        shareRequestToken={'shareRequestToken'}
                        setShareRequestToken={testLoginProps.setShareRequestToken}
                        acceptVCLink={null}
                        setAcceptVCLink={testLoginProps.setAcceptVCLink}
                        history = {history}
                    />
                </MemoryRouter>
            )
    
            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const submitButton = getByRole('button', {name: 'Login'});
    
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: 'test'
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: 'test'
                    }
                });
            })
    
    
            await act(async () => {
                await userEvent.click(submitButton);
            })
            expect(SdkService.prototype.fromLoginAndPassword).toBeCalledWith('test', 'test');
            expect(testLoginProps.userHasAuthenticated).toBeCalledWith(true);
            expect(console.log).not.toBeCalledWith('routing to accept page');
            expect(history.push).not.toBeCalledWith(`/accept-credentials?vcURL=acceptVCLink`);
            expect(console.log).toBeCalledWith('routing to share page');
            expect(history.push).toBeCalledWith(`/share-credentials?token=shareRequestToken`);
            expect(history.push).not.toBeCalledWith('/', 'test');
        });

        test ('login and route to /', async () => {
            const history = {
                push: jest.fn()
            };
            const testLoginProps = {
                isAuthenticated: false,
                userHasAuthenticated: jest.fn(x=>{}),
                setShareRequestToken: jest.fn(x=>{}),
                setAcceptVCLink: null,
            };
            window.alert = jest.fn((x)=>{})

            const { getByLabelText, getByRole } =render(
                <MemoryRouter>
                    <Login 
                        isAuthenticated={testLoginProps.isAuthenticated}
                        userHasAuthenticated={testLoginProps.userHasAuthenticated}
                        shareRequestToken={null}
                        setShareRequestToken={testLoginProps.setShareRequestToken}
                        acceptVCLink={null}
                        setAcceptVCLink={testLoginProps.setAcceptVCLink}
                        history = {history}
                    />
                </MemoryRouter>
            )
    
            const usernameField = getByLabelText('Username');
            const passwordField = getByLabelText('Password');
            const submitButton = getByRole('button', {name: 'Login'});
    
            act(() => {
                fireEvent.change(usernameField, {
                    target: {
                        value: 'test'
                    }
                });
    
                fireEvent.change(passwordField, {
                    target: {
                        value: 'test'
                    }
                });
            })
    
    
            await act(async () => {
                await userEvent.click(submitButton);
            })
            expect(SdkService.prototype.fromLoginAndPassword).toBeCalledWith('test', 'test');
            expect(testLoginProps.userHasAuthenticated).toBeCalledWith(true);
            expect(console.log).not.toBeCalledWith('routing to accept page');
            expect(history.push).not.toBeCalledWith(`/accept-credentials?vcURL=acceptVCLink`);
            expect(console.log).not.toBeCalledWith('routing to share page');
            expect(history.push).not.toBeCalledWith(`/share-credentials?token=shareRequestToken`);
            expect(history.push).toBeCalled();

        })
    
    });

    test("Fail to login", async () => {
        const { getByRole, getByLabelText } = render(
            <MemoryRouter>
                <Login />
            </MemoryRouter>
        );
        window.sdk = new SdkService();

        const error = new Error('This is a test');
        jest.spyOn(SdkService.prototype, 'fromLoginAndPassword').mockImplementation((username, password) => {
            throw error;
        });
        jest.spyOn(console, 'log').mockImplementation();

        const usernameField = getByLabelText('Username');
        const passwordField = getByLabelText('Password');
        const submitButton = getByRole('button', {name: 'Login'});

        act(() => {
            fireEvent.change(usernameField, {
                target: {
                    value: 'test'
                }
            });

            fireEvent.change(passwordField, {
                target: {
                    value: 'test'
                }
            });
        })

        await act(async () => {
            await userEvent.click(submitButton);
        })

        expect(window.alert).toBeCalledWith(error)
    })

    afterEach(()=>{
        jest.restoreAllMocks()
    });
})