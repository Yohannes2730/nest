// import { Controller, Post, Body } from '@nestjs/common';
// import { EmailService } from './email.service';

// @Controller('auth')
// export class EmailController {

//   constructor(private readonly emailService: EmailService) {}

//   @Post('verify-otp')
//   async verifyOtp(
//     @Body('email') email: string,
//     @Body('otp') otp: string,
//   ) {

//     return this.emailService.verifyOtp(email, otp);
//   }

//   @Post('resend-otp')
//   async resendOtp(@Body('email') email: string) {

//     await this.emailService.resendOtp(email);

//     return {
//       message: 'OTP resent successfully'
//     };
//   }
// }