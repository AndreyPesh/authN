import { ConflictException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { UserService } from '@user/user.service';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './interfaces';
import { compareSync } from 'bcrypt';
import { Token, User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '@prisma/prisma.service';
import { v4 } from 'uuid';
import { add } from 'date-fns';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly prismaService: PrismaService,
    ) {}

    async register(dto: RegisterDto) {
        const user: User = await this.userService.findOne(dto.email).catch((error) => {
            this.logger.error(error);
            return null;
        });
        if (user) {
            throw new ConflictException('User already exist!');
        }
        return this.userService.save(dto).catch((error) => {
            this.logger.error(error);
            return null;
        });
    }

    async login(dto: LoginDto): Promise<Tokens> {
        const user: User = await this.userService.findOne(dto.email).catch((error) => {
            this.logger.error(error);
            return null;
        });
        if (!user || !compareSync(dto.password, user.password)) {
            throw new UnauthorizedException('User not exist or wrong password!');
        }
        const accessToken = 'Bearer ' + this.jwtService.sign({
            id: user.id,
            email: user.email,
            roles: user.role,
        });
        const refreshToken = await this.getRefreshToken(user.id);
        return {
            accessToken,
            refreshToken,
        };
    }

    private async getRefreshToken(userId: string): Promise<Token> {
        return await this.prismaService.token.create({
            data: {
                token: v4(),
                exp: add(new Date(), { months: 1 }),
                userId,
            },
        });
    }
}
