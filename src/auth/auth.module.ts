import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { RefreshToken, RefreshTokenSchema } from './Schema/RefreshToken.schema';
import { User, userSchema } from './Schema/user.schema';
import { ResetToken, ResetTokenSchema } from './Schema/resetToken.schema';
import { EmailModule } from 'src/email/email.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: userSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema },

    ]),
        EmailModule, 

  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
