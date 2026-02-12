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

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {}

  async register(registerData: registerdto) {
    const { name, email, password } = registerData;

    const userExist = await this.userModel.findOne({ email });
    if (userExist) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new this.userModel({
      name,
      email,
      password: hashedPassword,
    });

    return newUser.save();
  }
  async login(credential: logindto) {
    const { email, password } = credential;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid credentials');
    }

    const tokens = await this.generateToken(user._id.toString());
    return {tokens,
      userId : user._id.toString()

    } 
  }

  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
       token: refreshToken ,
       expiresAt: { $gt: new Date() },
      });
    if (!token) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    return this.generateToken(token.userId.toString());
  }
  async generateToken(userId: string) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });

    const refreshToken = uuidv4();
    await this.StoreRefreshToken(refreshToken, userId);

    return {
      accessToken,
      refreshToken,
    };
  }
  async StoreRefreshToken(token: string, userId) {
    const expiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    expiryDate.setDate(expiryDate.getDate() + 7);
    await this.RefreshTokenModel.create({
      token,
      userId,
      expiresAt: expiryDate,
    });
  }
}
