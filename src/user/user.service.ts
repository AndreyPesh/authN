import { JwtPayload } from '@auth/interfaces';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { Role, User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { genSaltSync, hashSync } from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { convertToSecondsUtil } from '@common/utils';

@Injectable()
export class UserService {
    constructor(
        private readonly prismaService: PrismaService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private readonly configService: ConfigService,
    ) {}

    save(user: Partial<User>) {
        const hashPassword = this.hashPassword(user.password);
        return this.prismaService.user.create({
            data: {
                email: user.email,
                password: hashPassword,
                role: ['USER'],
            },
        });
    }

    async findOne(idOrEmail: string, isReset = false) {
        if (isReset) {
            await this.cacheManager.del(idOrEmail);
        }
        const user = await this.cacheManager.get<User>(idOrEmail);
        if (!user) {
            const user = this.prismaService.user.findFirst({
                where: {
                    OR: [{ id: idOrEmail }, { email: idOrEmail }],
                },
            });
            if (!user) return null;
            await this.cacheManager.set(idOrEmail, user, convertToSecondsUtil(this.configService.get('JWT_EXP')));
            return user;
        }
        return user;
    }

    async delete(id: string, user: JwtPayload) {
        if (user.id !== id && !user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException();
        }
        await Promise.all([await this.cacheManager.del(id), await this.cacheManager.del(user.email)]);
        return this.prismaService.user.delete({
            where: {
                id,
            },
            select: {
                id: true,
            },
        });
    }

    private hashPassword(password: string) {
        return hashSync(password, genSaltSync(10));
    }
}
