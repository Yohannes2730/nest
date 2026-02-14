import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { registerdto } from './dto/register.dto';
import { logindto } from './dto/login.dto';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './Schema/user.schema';
import { RefreshToken } from './Schema/RefreshToken.schema';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import {nanoid} from 'nanoid';
import { ResetToken } from './Schema/resetToken.schema';
import { MailService } from './services/mail.service';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name) private refreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name) private resetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService
  ) {}

  async register(registerData: registerdto) {
    const { name, email, password } = registerData;

    const userExist = await this.userModel.findOne({ email });
    if (userExist) throw new BadRequestException('Email already exists');

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new this.userModel({ name, email, password: hashedPassword });
    return newUser.save();
  }

  async login(credential: logindto) {
    const { email, password } = credential;

    const user = await this.userModel.findOne({ email });
    if (!user) throw new BadRequestException('Invalid credentials');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) throw new BadRequestException('Invalid credentials');

    const tokens = await this.generateToken(user._id.toString());
    return { tokens, userId: user._id.toString() };
  }
  
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.userModel.findById(userId);
    if (!user) throw new BadRequestException('User not found'); 

    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) throw new BadRequestException('Old password is incorrect');

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    return user.save();
  }
  async forgotPassword(email: string) {
    const user = await this.userModel.findOne({ email });
    const resetToken = nanoid(64);
    if (user) {
   const expiryDate = new Date()
    expiryDate.setHours(expiryDate.getHours() + 1); // Token valid for 1 hour
    await this.resetTokenModel.create({
       token: resetToken, 
       userId: user._id, 
       expiresAt: expiryDate });
       this.mailService.sendResetPasswordEmail(email, resetToken);
    }
  }
  async resetPassword(resetToken: string, newPassword: string) {
    const token = await this.resetTokenModel.findOne({ token: resetToken, 
      expiresAt: { $gt: new Date() } });
    if (!token) throw new UnauthorizedException('Invalid or expired reset token');
    const user = await this.userModel.findById(token.userId);
    if (!user) throw new BadRequestException('User not found');
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }
  async refreshTokens(refreshToken: string) {
    const token = await this.refreshTokenModel.findOne({
      token: refreshToken,
      expiresAt: { $gt: new Date() },
    });
    if (!token) throw new UnauthorizedException('Invalid or expired refresh token');

    return this.generateToken(token.userId.toString());
  }

  async generateToken(userId: string) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);

    return { accessToken, refreshToken };
  }

  async storeRefreshToken(token: string, userId: string) {
    const expiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await this.refreshTokenModel.create({ token, userId, expiresAt: expiryDate });
  }
}
