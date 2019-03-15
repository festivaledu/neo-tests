using System.Collections.Generic;
using System.Linq;
using Neo.Core.Authorization;
using Xunit;
using Xunit.Abstractions;

namespace Neo.Tests
{
    public class AuthorizationTests
    {
        private Dictionary<string, Permission> adminPermissions = new Dictionary<string, Permission> {
            { "neo.*", Permission.Allow }
        };

        private Dictionary<string, Permission> guestPermissions = new Dictionary<string, Permission> {
            { "neo.channel.join.$", Permission.Allow },
            { "neo.global.*", Permission.Allow }
        };

        private Dictionary<string, Permission> userPermissions = new Dictionary<string, Permission> {
            { "neo.channel.create", Permission.Allow }
        };

        private ITestOutputHelper output;

        public AuthorizationTests(ITestOutputHelper output) {
            this.output = output;
        }

        [Fact]
        public void AdminCanBanUser() {
            var unifiedPermissions = new Dictionary<string, Permission>();
            unifiedPermissions = new List<Dictionary<string, Permission>> { guestPermissions, userPermissions, adminPermissions }.Aggregate(unifiedPermissions, Authorizer.UnionPermissions);

            output.WriteLine(unifiedPermissions.Select(_ => $"{_.Key}: {_.Value}").Aggregate("", (c, n) => $"{c}{n}\n"));

            Assert.True(Authorizer.IsAuthorized("neo.moderate.ban", unifiedPermissions));
        }

        [Fact]
        public void AdminCanEditServer() {
            var unifiedPermissions = new Dictionary<string, Permission>();
            unifiedPermissions = new List<Dictionary<string, Permission>> { guestPermissions, userPermissions, adminPermissions }.Aggregate(unifiedPermissions, Authorizer.UnionPermissions);

            output.WriteLine(unifiedPermissions.Select(_ => $"{_.Key}: {_.Value}").Aggregate("", (c, n) => $"{c}{n}\n"));

            Assert.True(Authorizer.IsAuthorized("neo.server.edit", unifiedPermissions));
        }

        [Fact]
        public void GuestCanJoinChannel() {
            Assert.True(Authorizer.IsAuthorized("neo.channel.join.$", guestPermissions));
        }

        [Fact]
        public void GuestCanWrite() {
            Assert.True(Authorizer.IsAuthorized("neo.global.write", guestPermissions));
        }

        [Fact]
        public void GuestCantCreateChannel() {
            Assert.False(Authorizer.IsAuthorized("neo.channel.create", guestPermissions));
        }

        [Fact]
        public void GuestCantJoinChannelWithoutPassword() {
            Assert.False(Authorizer.IsAuthorized("neo.channel.join.ignorepassword", guestPermissions));
        }

        [Fact]
        public void UserCanCreateChannel() {
            var unifiedPermissions = new Dictionary<string, Permission>();
            unifiedPermissions = new List<Dictionary<string, Permission>> { guestPermissions, userPermissions }.Aggregate(unifiedPermissions, Authorizer.UnionPermissions);

            output.WriteLine(unifiedPermissions.Select(_ => $"{_.Key}: {_.Value}").Aggregate("", (c, n) => $"{c}{n}\n"));

            Assert.True(Authorizer.IsAuthorized("neo.channel.create", unifiedPermissions));
        }

        [Fact]
        public void UserCanWrite() {
            var unifiedPermissions = new Dictionary<string, Permission>();
            unifiedPermissions = new List<Dictionary<string, Permission>> { guestPermissions, userPermissions }.Aggregate(unifiedPermissions, Authorizer.UnionPermissions);

            output.WriteLine(unifiedPermissions.Select(_ => $"{_.Key}: {_.Value}").Aggregate("", (c, n) => $"{c}{n}\n"));

            Assert.True(Authorizer.IsAuthorized("neo.global.write", unifiedPermissions));
        }

        [Fact]
        public void UserCantKickUser() {
            var unifiedPermissions = new Dictionary<string, Permission>();
            unifiedPermissions = new List<Dictionary<string, Permission>> { guestPermissions, userPermissions }.Aggregate(unifiedPermissions, Authorizer.UnionPermissions);

            output.WriteLine(unifiedPermissions.Select(_ => $"{_.Key}: {_.Value}").Aggregate("", (c, n) => $"{c}{n}\n"));

            Assert.False(Authorizer.IsAuthorized("neo.moderate.kick", unifiedPermissions));
        }
    }
}
