import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { EmailService } from './email.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, userSchema } from 'src/auth/Schema/user.schema';
import { EmailOtp, EmailOtpSchema } from './entities/email.entity';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: EmailOtp.name, schema: EmailOtpSchema }, 
      { name: User.name, schema: userSchema },         
    ]),
    MailerModule.forRoot({
  transport: {
    host: 'smtp.mailtrap.io',
    port: 2525,
    secure: false,
    auth: {
      user: process.env.MAIL_USER, 
      pass: process.env.MAIL_PASSWORD, 
    },
  },
}),
  ],
  providers: [EmailService],
  exports: [EmailService],
})

export class EmailModule {}