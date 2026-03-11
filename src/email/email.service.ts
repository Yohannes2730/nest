import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { MailerService } from '@nestjs-modules/mailer';
import { User } from 'src/auth/Schema/user.schema';
import { EmailOtp } from './entities/email.entity';
import { randomInt } from 'crypto';

@Injectable()
export class EmailService {
  constructor(
    private readonly mailerService: MailerService,
    @InjectModel(EmailOtp.name)
    private readonly otpModel: Model<EmailOtp>,
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
  ) {}

  private generateOtp(): string {
    return randomInt(100000, 999999).toString();
  }

  async sendOtp(email: string ): Promise<{ message: string }> {
    if (!email) throw new BadRequestException('Email is required');

    const otp = this.generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);

    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 5);

    await this.otpModel.create({
      email,
      otpHash,
      expiresAt,
      verified: false,
      resendCount: 0,
      lastResendAt: new Date(),
    });

    await this.mailerService.sendMail({
      to: email,
      from: `"Your App Name" <${process.env.MAIL_USER}>`,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
      html: `<p>Your OTP code is <b>${otp}</b>. It will expire in 5 minutes.</p>`,
    });


    return { message: 'OTP sent to your email' };
  
  }

  async verifyOtp(email: string, otp: string) {
    if (!email) throw new BadRequestException('Email is required');

    const record = await this.otpModel
      .findOne({ email })
      .sort({ expiresAt: -1 })
      .exec();

    if (!record) throw new BadRequestException('OTP not found');
    if (record.expiresAt < new Date()) throw new BadRequestException('OTP expired');

    const isValid = await bcrypt.compare(otp, record.otpHash);
    if (!isValid) throw new BadRequestException('Invalid OTP');

    record.verified = true;
    await record.save();

    await this.userModel.updateOne({ email }, { $set: { verified: true } });

    return { message: 'Email verified successfully' };
  }

  async resendOtp(email: string): Promise<{ message: string }> {
    const record = await this.otpModel
      .findOne({ email })
      .sort({ expiresAt: -1 })
      .exec();

    const now = new Date();

    if (record) {
      record.resendCount = record.resendCount || 0;

      if (record.resendCount >= 3)
        throw new BadRequestException('Resend OTP limit reached');

      if (record.lastResendAt) {
        const diff = now.getTime() - new Date(record.lastResendAt).getTime();
        if (diff < 60000)
          throw new BadRequestException(
            'Please wait 60 seconds before resending OTP',
          );
      }

      record.resendCount += 1;
      record.lastResendAt = now;
      await record.save();
    }

    return this.sendOtp(email);
  }
}