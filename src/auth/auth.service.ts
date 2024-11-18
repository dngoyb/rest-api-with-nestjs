import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async singup(dto: AuthDto) {
    try {
      // Generate the password
      const hash = await argon.hash(dto.password);

      //Save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      //Returned the saved user
      delete user.hash;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('User Already exist');
        }
      }
      throw error;
    }
  }

  async singin(dto: AuthDto) {
    //Find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    //if user doesnt exist throw exception
    if (!user) throw new ForbiddenException('User not found');

    //compare password
    const pwMatches = await argon.verify(user.hash, dto.password);

    //if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException('User not found');

    //send back the user
    delete user.hash;

    return user;
  }
}
