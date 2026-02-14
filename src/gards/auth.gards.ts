import { Injectable, CanActivate, ExecutionContext, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);

    if (!token) throw new UnauthorizedException('No token provided');

    try {
      const payload = this.jwtService.verify(token);
      request['userId'] = payload.userId;
      return true;
    } catch (error) {
      Logger.error(error.message);
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    return request.headers['authorization']?.split(' ')[1];
  }
}
