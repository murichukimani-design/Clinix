import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import prisma from '@config/database';
import { AppError } from '@middleware/errorHandler';
import { logger } from '@utils/logger';
import * as emailService from '@services/email.service';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '7d';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '30d';

interface RegisterPayload {
  email: string;
  firstName: string;
  lastName: string;
  password: string;
  tenantId?: string;
  branchId?: string;
}

interface LoginPayload {
  email: string;
  password: string;
  rememberMe: boolean;
  ipAddress?: string;
  userAgent?: string;
}

export const register = async (payload: RegisterPayload) => {
  try {
    const { email, firstName, lastName, password, tenantId, branchId } = payload;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: { email },
    });

    if (existingUser) {
      throw new AppError('Email already registered', 409);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate email verification token
    const emailVerificationToken = uuidv4();
    const emailVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        password: hashedPassword,
        tenantId: tenantId || '',
        branchId,
        emailVerificationToken,
        emailVerificationExpiry,
      },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    // Send verification email
    await emailService.sendVerificationEmail(user.email, emailVerificationToken);

    logger.info(`User registered: ${user.email}`);

    return {
      message: 'Registration successful. Please verify your email.',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    };
  } catch (error) {
    logger.error('Registration error:', error);
    throw error;
  }
};

export const login = async (payload: LoginPayload) => {
  try {
    const { email, password, rememberMe, ipAddress, userAgent } = payload;

    // Find user
    const user = await prisma.user.findFirst({
      where: { email },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user) {
      throw new AppError('Invalid credentials', 401);
    }

    // Check if email is verified
    if (!user.emailVerified) {
      throw new AppError('Please verify your email before logging in', 403);
    }

    // Check if account is active
    if (!user.isActive) {
      throw new AppError('Your account has been deactivated', 403);
    }

    // Check if account is locked
    if (user.isLocked && user.lockExpiresAt && user.lockExpiresAt > new Date()) {
      throw new AppError('Your account is locked. Please try again later.', 423);
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Increment login attempts
      const newLoginAttempts = user.loginAttempts + 1;
      
      if (newLoginAttempts >= 5) {
        // Lock account for 30 minutes
        await prisma.user.update({
          where: { id: user.id },
          data: {
            loginAttempts: newLoginAttempts,
            isLocked: true,
            lockExpiresAt: new Date(Date.now() + 30 * 60 * 1000),
            lockReason: 'Too many failed login attempts',
          },
        });

        throw new AppError('Account locked due to too many failed attempts', 423);
      }

      await prisma.user.update({
        where: { id: user.id },
        data: { loginAttempts: newLoginAttempts },
      });

      throw new AppError('Invalid credentials', 401);
    }

    // Reset login attempts on successful login
    await prisma.user.update({
      where: { id: user.id },
      data: {
        loginAttempts: 0,
        isLocked: false,
        lastLogin: new Date(),
        lastLoginIp: ipAddress,
        lastLoginUserAgent: userAgent,
      },
    });

    // Collect permissions
    const permissions = user.roles.flatMap((ur) =>
      ur.role.permissions.map((rp) => rp.permission.slug),
    );

    // Generate tokens
    const accessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      tenantId: user.tenantId,
      role: user.roles[0]?.role.slug || 'user',
      permissions,
    });

    const refreshToken = generateRefreshToken({
      userId: user.id,
      email: user.email,
    });

    // Create session
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await prisma.session.create({
      data: {
        userId: user.id,
        token: accessToken,
        refreshToken,
        ipAddress,
        userAgent,
        expiresAt,
      },
    });

    logger.info(`User logged in: ${user.email}`);

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar,
        tenantId: user.tenantId,
        branchId: user.branchId,
        roles: user.roles.map((ur) => ur.role.slug),
        permissions,
      },
    };
  } catch (error) {
    logger.error('Login error:', error);
    throw error;
  }
};

export const refreshToken = async (token: string) => {
  try {
    // Verify refresh token
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    // Find user
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user || !user.isActive) {
      throw new AppError('User not found or account is inactive', 401);
    }

    // Collect permissions
    const permissions = user.roles.flatMap((ur) =>
      ur.role.permissions.map((rp) => rp.permission.slug),
    );

    // Generate new access token
    const accessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      tenantId: user.tenantId,
      role: user.roles[0]?.role.slug || 'user',
      permissions,
    });

    logger.info(`Token refreshed for user: ${user.email}`);

    return { accessToken };
  } catch (error) {
    logger.error('Token refresh error:', error);
    throw new AppError('Invalid or expired refresh token', 401);
  }
};

export const logout = async (refreshToken: string) => {
  try {
    // Invalidate session
    await prisma.session.updateMany({
      where: { refreshToken },
      data: { isActive: false },
    });

    logger.info('User logged out');
  } catch (error) {
    logger.error('Logout error:', error);
  }
};

export const verifyEmail = async (token: string) => {
  try {
    const user = await prisma.user.findFirst({
      where: {
        emailVerificationToken: token,
        emailVerificationExpiry: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      throw new AppError('Invalid or expired verification token', 400);
    }

    // Mark email as verified
    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpiry: null,
      },
    });

    logger.info(`Email verified for user: ${user.email}`);

    return { message: 'Email verified successfully' };
  } catch (error) {
    logger.error('Email verification error:', error);
    throw error;
  }
};

export const resendVerification = async (email: string) => {
  try {
    const user = await prisma.user.findFirst({
      where: { email },
    });

    if (!user) {
      throw new AppError('User not found', 404);
    }

    if (user.emailVerified) {
      throw new AppError('Email already verified', 400);
    }

    const emailVerificationToken = uuidv4();
    const emailVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerificationToken,
        emailVerificationExpiry,
      },
    });

    await emailService.sendVerificationEmail(email, emailVerificationToken);

    logger.info(`Verification email resent to: ${email}`);
  } catch (error) {
    logger.error('Resend verification error:', error);
    throw error;
  }
};

export const forgotPassword = async (email: string) => {
  try {
    const user = await prisma.user.findFirst({
      where: { email },
    });

    if (!user) {
      throw new AppError('User not found', 404);
    }

    const passwordResetToken = uuidv4();
    const passwordResetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken,
        passwordResetExpiry,
      },
    });

    await emailService.sendPasswordResetEmail(email, passwordResetToken);

    logger.info(`Password reset email sent to: ${email}`);
  } catch (error) {
    logger.error('Forgot password error:', error);
    throw error;
  }
};

export const resetPassword = async (token: string, newPassword: string) => {
  try {
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetExpiry: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      throw new AppError('Invalid or expired reset token', 400);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpiry: null,
      },
    });

    logger.info(`Password reset for user: ${user.email}`);

    return { message: 'Password reset successfully' };
  } catch (error) {
    logger.error('Reset password error:', error);
    throw error;
  }
};

// Helper functions
const generateAccessToken = (payload: any) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
};

const generateRefreshToken = (payload: any) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
};
