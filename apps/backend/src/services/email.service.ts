import nodemailer from 'nodemailer';
import { logger } from '@utils/logger';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: process.env.SMTP_PORT === '465',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

interface EmailPayload {
  to: string;
  subject: string;
  html: string;
}

const sendEmail = async (payload: EmailPayload) => {
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'noreply@clinix.com',
      ...payload,
    });

    logger.info(`Email sent to: ${payload.to}`);
  } catch (error) {
    logger.error('Email sending error:', error);
    throw error;
  }
};

export const sendVerificationEmail = async (email: string, token: string) => {
  const verificationLink = `${CLIENT_URL}/verify-email?token=${token}`;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Welcome to Clinix HMIS</h2>
      <p>Thank you for registering with us. Please verify your email address by clicking the link below:</p>
      <p>
        <a href="${verificationLink}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
          Verify Email
        </a>
      </p>
      <p>Or copy and paste this link in your browser:</p>
      <p>${verificationLink}</p>
      <p>This link will expire in 24 hours.</p>
      <hr />
      <p style="font-size: 12px; color: #666;">If you did not register for this account, please ignore this email.</p>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: 'Verify your Clinix HMIS Email',
    html,
  });
};

export const sendPasswordResetEmail = async (email: string, token: string) => {
  const resetLink = `${CLIENT_URL}/reset-password?token=${token}`;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Password Reset Request</h2>
      <p>We received a request to reset your password. Click the link below to create a new password:</p>
      <p>
        <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">
          Reset Password
        </a>
      </p>
      <p>Or copy and paste this link in your browser:</p>
      <p>${resetLink}</p>
      <p>This link will expire in 1 hour.</p>
      <hr />
      <p style="font-size: 12px; color: #666;">If you did not request a password reset, please ignore this email or contact support.</p>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: 'Reset your Clinix HMIS Password',
    html,
  });
};

export const sendWelcomeEmail = async (
  email: string,
  firstName: string,
  tenantName: string,
) => {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Welcome to ${tenantName}</h2>
      <p>Hi ${firstName},</p>
      <p>Your account has been successfully created. You can now log in to the Clinix HMIS system.</p>
      <p>
        <a href="${CLIENT_URL}/login" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
          Login to Clinix HMIS
        </a>
      </p>
      <hr />
      <p style="font-size: 12px; color: #666;">If you have any questions, please contact your administrator.</p>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: `Welcome to ${tenantName} - Clinix HMIS`,
    html,
  });
};

export const sendAccountLockedEmail = async (email: string, unlockTime: Date) => {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #dc3545;">Account Temporarily Locked</h2>
      <p>Your account has been locked due to multiple failed login attempts.</p>
      <p>Your account will be automatically unlocked at: <strong>${unlockTime.toLocaleString()}</strong></p>
      <p>If this wasn't you, please contact your administrator immediately.</p>
      <hr />
      <p style="font-size: 12px; color: #666;">For security concerns, please reach out to our support team.</p>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: 'Clinix HMIS - Account Locked',
    html,
  });
};

export const sendRoleAssignmentEmail = async (
  email: string,
  firstName: string,
  roleName: string,
) => {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Role Assignment Notification</h2>
      <p>Hi ${firstName},</p>
      <p>Your role has been updated to: <strong>${roleName}</strong></p>
      <p>This may change your access permissions in the system.</p>
      <hr />
      <p style="font-size: 12px; color: #666;">If you believe this is an error, please contact your administrator.</p>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: 'Clinix HMIS - Role Assignment',
    html,
  });
};

export const sendBulkNotificationEmail = async (
  emails: string[],
  subject: string,
  htmlContent: string,
) => {
  try {
    for (const email of emails) {
      await sendEmail({
        to: email,
        subject,
        html: htmlContent,
      });
    }
  } catch (error) {
    logger.error('Bulk email sending error:', error);
    throw error;
  }
};
