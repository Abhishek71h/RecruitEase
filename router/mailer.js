import nodemailer from 'nodemailer';

const mailer = async (mailContent, email) => {
  const testAccount = await nodemailer.createTestAccount();

  const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass
    }
  });

  const mailOptions = {
    from: '"RecruitEase Team" <noreply@recruitease.com>',
    to: email,
    subject: 'RecruitEase Password Reset Link',
    html: mailContent
  };

  const info = await transporter.sendMail(mailOptions);
  return nodemailer.getTestMessageUrl(info); // ✅ return preview URL
};

export default mailer;
