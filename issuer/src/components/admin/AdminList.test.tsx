import React from "react";
import AdminList from "components/admin/AdminList";
import { act, render } from "@testing-library/react";
import {createMemoryHistory} from 'history';
import { Router, MemoryRouter } from 'react-router-dom';
import userEvent from '@testing-library/user-event'

const history = createMemoryHistory()

const mockData = {
  approved: false,
  username: "tester",
  applicationID: "0000000",
  payload: {
      givenName: "trest",
      holderDid: "did:elem:EiCUQ8lQ4FnbNO5jFQaEMGnZ8uPO46VEUTicvd3ky8YZnQ;elem:initial-state=eyJwcm90ZWN0ZWQiOiJleUp2Y0dWeVlYUnBiMjRpT2lKamNtVmhkR1VpTENKcmFXUWlPaUlqY0hKcGJXRnllU0lzSW1Gc1p5STZJa1ZUTWpVMlN5SjkiLCJwYXlsb2FkIjoiZXlKQVkyOXVkR1Y0ZENJNkltaDBkSEJ6T2k4dmR6TnBaQzV2Y21jdmMyVmpkWEpwZEhrdmRqSWlMQ0p3ZFdKc2FXTkxaWGtpT2x0N0ltbGtJam9pSTNCeWFXMWhjbmtpTENKMWMyRm5aU0k2SW5OcFoyNXBibWNpTENKMGVYQmxJam9pVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T0NJc0luQjFZbXhwWTB0bGVVaGxlQ0k2SWpBelltRTRPV1EzTURZeVlqaGpNREF4WWpZd1lUSXlNakE0TVdJME5ERmpNV1EzTURBek9UTTVPREk1Wldaa05tTTFabU14WTJJNU4yVTBORFkzWXpJMk1TSjlMSHNpYVdRaU9pSWpjbVZqYjNabGNua2lMQ0oxYzJGblpTSTZJbkpsWTI5MlpYSjVJaXdpZEhsd1pTSTZJbE5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGdpTENKd2RXSnNhV05MWlhsSVpYZ2lPaUl3TWpBellqWXlOR00xWmpFek56QXpORFJtWWpnMVpqZGhPV1EyWVRZMlpUVmlaalpqTlRSaU1XSXlNRFEyTURJeFptVXpZakl3WlRNNU56WTNZalpqWmpZaWZWMHNJbUYxZEdobGJuUnBZMkYwYVc5dUlqcGJJaU53Y21sdFlYSjVJbDBzSW1GemMyVnlkR2x2YmsxbGRHaHZaQ0k2V3lJamNISnBiV0Z5ZVNKZGZRIiwic2lnbmF0dXJlIjoiRDVCZ1BYaGlreDU2dl9YNDBkVjRtZ2RQbnUtblBBNmc5c0gwemNEclpIWW42cEQyZHlocmpLTU9lT01UTXoxOFROcE0xZW1kMmZCaFdiLXZ6SmtsLVEifQ",
      familyName: "yete",
      idClass: "{\"drivingLicenseID\":\"whuifhwf\",\"country\":\"Singapore\",\"drivingClass\":\"3\",\"email\":\"test@gmail.com\",\"issuerOrganization\":\"Automobile Association of Singapore\",\"affinidiDrivingLicenseID\":\"VNFkSM8rF2\"}",
      issueDate: "10/10/2018"
  },
  docID: "UvF3osjYVncXjrxElpnI"
}

const mockHistoryPush = jest.fn();

jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useHistory: () => ({
    push: mockHistoryPush,
  }),
}));

describe("AdminList Component Test", () => {

  test("Renders the component", () => {
    const { getByText, getByRole } = render(    
      <MemoryRouter>
        <AdminList data={mockData}/>
      </MemoryRouter>
    )

    const applicationNumber = getByText(/Application ID:/i)
    const viewMoreButton = getByRole('button', {name: 'View more'});

    expect(applicationNumber).toBeInTheDocument();
    expect(viewMoreButton).toBeInTheDocument();
  });

  test("Button calls history.push", () => {
    const { getByRole } = render(
      <Router history={history}>
        <AdminList data={mockData}/>
      </Router>
    );

    const viewMoreButton = getByRole('button', {name: 'View more'});

    userEvent.click(viewMoreButton);
    expect(mockHistoryPush).toHaveBeenCalledTimes(1)
  })

});