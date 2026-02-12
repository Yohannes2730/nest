import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { registerdto} from './dto/register.dto';
import { logindto } from './dto/login.dto';
import { refreshTokenDto } from './dto/refreshToken.dto';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registerData: registerdto) {
    return this.authService.register(registerData);
  }

  @Post('login')
  async login(@Body() Credential: logindto){
    return this.authService.login(Credential);

  }

@Post('refresh')
async refreshToken(@Body() refreshTokenDto: refreshTokenDto) {
  return this.authService.refreshTokens(refreshTokenDto.token); 

}
}