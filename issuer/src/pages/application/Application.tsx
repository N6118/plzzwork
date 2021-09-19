import React, { useState, useContext } from 'react';
import AppContext from 'context/app';
import {Button, Form} from 'react-bootstrap';
import ApiService from 'utils/apiService';
import 'pages/application/Application.scss'
import firebase from 'utils/firebase/firebase';
import randomstring from 'randomstring';

interface IBaseVCData {
  givenName: string;
  familyName: string;
  issueDate: string;
}

interface IExtendVCData {
  drivingLicenseID: string;
  country: string;
  drivingClass: string;
  email: string;
  issuerOrganization: string;
}

const defaultBaseVCData: IBaseVCData = {
  givenName: '',
  familyName: '',
  issueDate: ''
}

const defaultExtendVCData: IExtendVCData = {
  drivingLicenseID: '',
  country: 'Singapore',
  drivingClass: '1',
  email: '',
  issuerOrganization: 'Automobile Association of Singapore'
}

interface IPayload extends IBaseVCData{
  idClass: string;
  holderDid: string
}

const Application: React.FC = (): React.ReactElement => {
    const {appState} = useContext(AppContext);
    const [inputDID, setinputDID] = useState(appState.didToken || '');

    const [baseVCData, setBaseVCData] = useState<IBaseVCData>(defaultBaseVCData);
  
    const [extendVCData, setExtendVCData] = useState<IExtendVCData>(defaultExtendVCData);
    const [validated, setValidated] = useState(false);

    /**
     * Function for issuing an unsigned employment VC.
     * */

    const issueDrivingLicensePersonVC = async () => {
      try {
    
        setValidated(true);

        const { givenName, familyName, issueDate } = baseVCData;

        // Generate a random Affinidi Driving License ID, which will double up as an application ID
        const applicationID: string = randomstring.generate(10);
        const vcToStringify = {...extendVCData, affinidiDrivingLicenseID: applicationID}
        
        const payload: IPayload = {
          givenName,
          familyName,
          issueDate,
          idClass: JSON.stringify(vcToStringify),
          holderDid: inputDID || appState.didToken || '',
        }

        // Store unsignedVC into issuer's datsabase
        const db = firebase.firestore();
        db.collection('drivinglicense-waiting-approval').add({username: appState.username, payload, applicationID, approved: false})

        alert('You have successfully submitted your application.');
      } catch (error) {
          ApiService.alertWithBrowserConsole(error.message);
      }
    }

    const handleSubmit = (event: any) => {
      const form = event.currentTarget;
        event.preventDefault();
        event.stopPropagation();
      if (form.checkValidity() === true) {
        issueDrivingLicensePersonVC()
      }
  
      setValidated(true);
    };
    
    const resetToDefaults = () => {
      setinputDID(appState.didToken || '')

      setBaseVCData(defaultBaseVCData)
      setExtendVCData(defaultExtendVCData)
    }
    
    const updateBaseVC = (e: any) => {
      setBaseVCData({...baseVCData, [e.target.name]: e.target.value})
    }

    const updateExtendBaseVC = (e: any) => {
      setExtendVCData({...extendVCData, [e.target.name]: e.target.value})
    }

    return (
      <div className='tutorial'>
        <div className='tutorial__step'>
          <Button 
            style={{float: 'right'}}
            onClick={e => resetToDefaults()}
            >Clear all fields
          </Button>

          <p><strong>Step 1:</strong>Please fill in details of your Project</p>
          <Form noValidate validated={validated} onSubmit={handleSubmit}>
            <Form.Group controlId='email'>
              <Form.Label className='label' style={{margin: '10px 0 0 0'}}>Email Address:</Form.Label>
              <Form.Control required name='email' type='text' value={extendVCData.email} onChange={e => updateExtendBaseVC(e)}/>
              <Form.Control.Feedback type="invalid">Please provide a valid Email Address.</Form.Control.Feedback>
            </Form.Group>

            <Form.Group controlId='givenName'>
              <Form.Label className='label' style={{margin: '10px 0 0 0'}}>Company Name:</Form.Label>
              <Form.Control required name='givenName' type='text' value={baseVCData.givenName} onChange={e => updateBaseVC(e)}/>
              <Form.Control.Feedback type="invalid"> Please provide a Given Name. </Form.Control.Feedback>
            </Form.Group>

            <Form.Group controlId='familyName'>
              <Form.Label style={{margin: '10px 0 0 0'}}>Project Name</Form.Label>
              <Form.Control required name='familyName' type='text' value={baseVCData.familyName} onChange={e => updateBaseVC(e)}/>
              <Form.Control.Feedback type="invalid"> Please provide a Family Name. </Form.Control.Feedback>
            </Form.Group>

            <Form.Group controlId='issueDate'>
              <Form.Label style={{margin: '10px 0 0 0'}}>Description of capitals to be used in Project</Form.Label>
              <Form.Control required name='issueDate' type='text' value={baseVCData.issueDate} onChange={e => updateBaseVC(e)}/>
              <Form.Control.Feedback type="invalid"> Please provide a Date. </Form.Control.Feedback>
            </Form.Group>

            <Form.Group controlId='drivingLicense'>
              <Form.Label style={{margin: '10px 0 0 0'}}>Expected Time Of Completion</Form.Label>
              <Form.Control required name='drivingLicenseID' type='text' value={extendVCData.drivingLicenseID} onChange={e => updateExtendBaseVC(e)}/>
              <Form.Control.Feedback type="invalid"> Please provide a valid Driving License ID. </Form.Control.Feedback>
            </Form.Group>

            <Form.Group controlId='drivingClass'>
              <Form.Label style={{margin: '10px 0 0 0'}}>Level Of Project</Form.Label>
              <Form.Control name='drivingClass' as="select" value={extendVCData.drivingClass} onChange={e => updateExtendBaseVC(e)}>
                <option>National Level</option>
                <option>State Level</option>
                <option>Destrict Level</option>
                <option>City/Rural Area</option>
              </Form.Control>
            </Form.Group>

            <div style={{margin: '30px 0'}}>
              <p><strong>Step 2:</strong>Upload Proof Of Contract</p>
              <Form.File id="formcheck-api-regular">
                <Form.File.Label>Proof of Contract</Form.File.Label>
                <Form.File.Input />
                <Form.Control.Feedback type="invalid"> Please provide proof of Contract</Form.Control.Feedback>
              </Form.File>
            </div>
            
            <Button 
              type="submit"
              >Submit
            </Button>
          </Form>
        </div>
      </div>
    )
}

export default Application;