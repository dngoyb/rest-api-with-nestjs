import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { jwtStrategy } from './strategy';

@Module({
  imports: [PrismaModule, JwtModule.register({})],
  providers: [AuthService, jwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
