import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';


@Schema({ collection: 'email_otps', timestamps: true })
export class EmailOtp {
  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  otpHash: string;

  @Prop({ required: true })
  expiresAt: Date;

  @Prop({ default: false })
  verified: boolean;

  @Prop({ default: 0 })
  resendCount: number;

  @Prop({ default: 0 })
  attemptCount: number;

  @Prop()
  lastResendAt: Date;
}

export const EmailOtpSchema = SchemaFactory.createForClass(EmailOtp);