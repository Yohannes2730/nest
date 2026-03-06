import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { MongoRepository } from 'typeorm';
import { EmailOtp } from './entities/email.entity';
import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';

@Injectable()
export class EmailService {
  constructor(
    @InjectRepository(EmailOtp)
    private readonly otpRepository: MongoRepository<EmailOtp>,
  ) {}
  generateOtp(): string {
    return randomInt(100000, 999999).toString();
  }

  async createOtp(email: string) {
    const otp = this.generateOtp();

    const otpHash = await bcrypt.hash(otp, 10);

    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 5);

    const otpRecord = this.otpRepository.create({
      email,
      otpHash,
      expiresAt,
      verified: false,
      resendCount: 0,
      lastResendAt: new Date(),
    });

    await this.otpRepository.save(otpRecord);

    return otp;
  }

  async verifyOtp(email: string, otp: string) {
    const record = await this.otpRepository.findOne({
      where: { email },
      order: { expiresAt: 'DESC' },
    });
    if (!email) throw new BadRequestException('User not found');
    if (!record) throw new BadRequestException('OTP not found');

    if (record.expiresAt < new Date())
      throw new BadRequestException('OTP expired');

    const isValid = await bcrypt.compare(otp, record.otpHash);

    if (!isValid) throw new BadRequestException('Invalid OTP');

    record.verified = true;

    await this.otpRepository.save(record);

    return { message: 'Email verified successfully' };
  }

  async resendOtp(email: string) {
    let record = await this.otpRepository.findOne({
      where: { email },
      order: { expiresAt: 'DESC' },
    });
    if (!email) throw new BadRequestException('User not found');
    const now = new Date();

    if (record) {
      if (!record.resendCount) record.resendCount = 0;

      if (record.resendCount >= 3)
        throw new BadRequestException('Resend OTP limit reached');

      if (record.lastResendAt) {
        const diff = now.getTime() - new Date(record.lastResendAt).getTime();

        if (diff < 60)
          throw new BadRequestException(
            'Please wait 60 seconds before resending OTP',
          );
      }

      record.resendCount += 1;
      record.lastResendAt = now;

      await this.otpRepository.save(record);
    }

    return this.createOtp(email);
  }
}
