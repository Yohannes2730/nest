import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Put,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { registerdto} from './dto/register.dto';
import { logindto } from './dto/login.dto';
import { refreshTokenDto } from './dto/refreshToken.dto';
import { ChangePasswordDto } from './dto/ChangePassword.dto';
import { AuthGuard } from '../gards/auth.gards';
import { ForgotPasswordDto } from './dto/ForgotPassword.dto';
import { ResetPasswordDto } from './dto/resetePassword.dto';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
async register(@Body() registerData: registerdto) {
  try {
    return await this.authService.register(registerData);
  } catch (err) {
    console.error(err);
    throw err;
  }
}


  @Post('login')
  async login(@Body() Credential: logindto){
    return this.authService.login(Credential);

  }

@Post('refresh')
async refreshToken(@Body() refreshTokenDto: refreshTokenDto) {
  return this.authService.refreshTokens(refreshTokenDto.token);
}
  
  @UseGuards(AuthGuard)
  @Put('change-password')
  async changePassword(@Body() changePasswordDto: ChangePasswordDto,@Req() req) {
    return this.authService.changePassword(req.user.id, changePasswordDto.oldPassword, changePasswordDto.newPassword);
}
@Post('forgot-password')
async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
  return this.authService.forgotPassword(forgotPasswordDto.email);  
}
@Put('reset-password')
async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
  return this.authService.resetPassword(resetPasswordDto.resetToken, resetPasswordDto.newPassword);
}
}