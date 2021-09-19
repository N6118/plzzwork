import emailjs from 'emailjs-com';
import config from '../config';

// Sender email
const sender_email = 'no-reply@vc-generator.com';

export const sendEmail = (
  qrCode: string,
  sharingUrl: string,
  receiver_email: string
) => {
  if (
    config.emailJsServiceID &&
    config.emailJsTemplateID &&
    config.emailJsUserID
  ) {
    emailjs
      .send(
        config.emailJsServiceID,
        config.emailJsTemplateID,
        {
          receiver_email: receiver_email,
          link: `${config.wallet_url}/accept-credentials?vcURL=${sharingUrl}`,
        },
        config.emailJsUserID
      )
      .then(
        function (response) {
          console.log('SUCCESS!', response.status, response.text);
        },
        function (error) {
          console.log('FAILED...', error);
        }
      );
  }
};
