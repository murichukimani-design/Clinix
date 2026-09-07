import type { Request, Response } from 'express';
import * as authService from '@services/auth.service';
import { AppError } from '@middleware/errorHandler';

export const register = async (req: Request, res: Response) => {
  const { email, firstName, lastName, password, tenantId, branchId } = req.body;

  if (!email || !firstName || !lastName || !password) {
    throw new AppError('Missing required fields', 400);
  }

  const result = await authService.register({
    email,
    firstName,
    lastName,
    password,
    tenantId,
    branchId,
  });

  res.status(201).json(result);
};

export const login = async (req: Request, res: Response) => {
  const { email, password, rememberMe } = req.body;

  if (!email || !password) {
    throw new AppError('Email and password are required', 400);
  }

  const result = await authService.login({
    email,
    password,
    rememberMe: rememberMe || false,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
  });

  // Set secure cookies
  res.cookie('accessToken', result.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.cookie('refreshToken', result.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  res.json(result);
};

export const refreshToken = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new AppError('Refresh token is required', 400);
  }

  const result = await authService.refreshToken(refreshToken);

  res.cookie('accessToken', result.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json(result);
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    await authService.logout(refreshToken);
  }

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  res.json({ message: 'Logged out successfully' });
};

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    throw new AppError('Verification token is required', 400);
  }

  const result = await authService.verifyEmail(token);

  res.json(result);
};

export const resendVerification = async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError('Email is required', 400);
  }

  await authService.resendVerification(email);

  res.json({ message: 'Verification email sent successfully' });
};

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError('Email is required', 400);
  }

  await authService.forgotPassword(email);

  res.json({ message: 'Password reset link sent to your email' });
};

export const resetPassword = async (req: Request, res: Response) => {
  const { token, password, confirmPassword } = req.body;

  if (!token || !password || !confirmPassword) {
    throw new AppError('Missing required fields', 400);
  }

  if (password !== confirmPassword) {
    throw new AppError('Passwords do not match', 400);
  }

  const result = await authService.resetPassword(token, password);

  res.json(result);
};
