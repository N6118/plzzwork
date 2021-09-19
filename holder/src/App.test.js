import React from 'react';
import {render} from '@testing-library/react';
import {Router} from 'react-router-dom';
import { createMemoryHistory } from 'history';
import App from './App'
import userEvent from '@testing-library/user-event';

const history = createMemoryHistory()
jest.mock('./utils/sdkService');
jest.mock('./utils/messageService', ()=>({
    MessageService: jest.fn()
}));

describe('App component test', () => {
    test('App component when user is not logged in will show Sign Up and Login link', async ()=>{
        const { queryByRole } = render(<Router history={history}>
            <App 
                history = {history}
            />
        </Router>)
        
        expect(queryByRole('link', {name: 'Sign Up'})).toBeTruthy();
        expect(queryByRole('link', {name: 'Login'})).toBeTruthy();
    })

    test('User can click on signup link and route to /signup', ()=>{
        const { getByRole } = render(<Router history={history}>
            <App 
                history = {history}
            />
        </Router>)
        const signUpLink = getByRole('link', {name: 'Sign Up'});
        userEvent.click(signUpLink);
        expect(history.location.pathname).toEqual('/signup');
    })

    test('User can click on the login link and route to /login', ()=>{
        const { getAllByRole } = render(<Router history={history}>
            <App 
                history = {history}
            />
        </Router>)
        const loginLink = getAllByRole('link', {name: 'Login'})[0];
        userEvent.click(loginLink);
        expect(history.location.pathname).toEqual('/login');
    })
})