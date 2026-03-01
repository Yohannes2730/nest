import {
  Controller,
  Post,
  Put,
  Body,
  UseGuards,
  Req,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { registerdto } from './dto/register.dto';
import { logindto } from './dto/login.dto';
import { refreshTokenDto } from './dto/refreshToken.dto';
import { ChangePasswordDto } from './dto/ChangePassword.dto';
import { AuthGuard } from '../gards/auth.gards';
import { ForgotPasswordDto } from './dto/ForgotPassword.dto';
import { ResetPasswordDto } from './dto/resetePassword.dto';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registerData: registerdto) {
    try {
      return await this.authService.register(registerData);
    } catch (err) {
      console.error('Register Error:', err.message);
      throw new HttpException('Internal Server Error', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('login')
  async login(@Body() credential: logindto) {
    try {
      return await this.authService.login(credential);
    } catch (err) {
      console.error('Login Error:', err.message);
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('refresh')
  async refreshToken(@Body() dto: refreshTokenDto) {
    try {
      return await this.authService.refreshTokens(dto.token);
    } catch (err) {
      console.error('Refresh Token Error:', err.message);
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
    }
  }

  @UseGuards(AuthGuard)
  @Put('change-password')
  async changePassword(@Body() dto: ChangePasswordDto, @Req() req: Request & { user: { id: string } }) {
    try {
      return await this.authService.changePassword(req.user.id, dto.oldPassword, dto.newPassword);
    } catch (err) {
      console.error('Change Password Error:', err.message);
      throw new HttpException('Failed to change password', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    try {
      return await this.authService.forgotPassword(dto.email);
    } catch (err) {
      console.error('Forgot Password Error:', err.message);
      throw new HttpException('Failed to send reset email', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Put('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    try {
      return await this.authService.resetPassword(dto.resetToken, dto.newPassword);
    } catch (err) {
      console.error('Reset Password Error:', err.message);
      throw new HttpException('Failed to reset password', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
