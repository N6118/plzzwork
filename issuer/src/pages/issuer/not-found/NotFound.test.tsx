import React from 'react';
import {render} from '@testing-library/react';
import NotFound from './NotFound'


describe('Test NotFound component', ()=>{
    test('UI can render', ()=>{
        const { queryByText } = render(<NotFound />);
        expect(queryByText('404')).toBeTruthy();
    })
})