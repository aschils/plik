// Modal dialog service
angular.module('dialog', ['ui.bootstrap']).factory('$dialog', function ($uibModal) {

    var module = {};

    // Define error partial here so we can display a connection error
    // without having to load the template from the server
    var alertTemplate = '<div class="modal-header">' + "\n";
    alertTemplate += '<h1>{{title}}</h1>' + "\n";
    alertTemplate += '</div>' + "\n";
    alertTemplate += '<div class="modal-body">' + "\n";
    alertTemplate += '<p>{{message}}</p>' + "\n";
    alertTemplate += '<p ng-show="data.value">' + "\n";
    alertTemplate += '{{value}}' + "\n";
    alertTemplate += '</p>' + "\n";
    alertTemplate += '</div>' + "\n";
    alertTemplate += '<div class="modal-footer" ng-if="confirm">' + "\n";
    alertTemplate += '<button ng-click="$dismiss()" class="btn btn-danger">Cancel</button>' + "\n";
    alertTemplate += '<button ng-click="$close()" class="btn btn-success">OK</button>' + "\n";
    alertTemplate += '</div>' + "\n";
    alertTemplate += '<div class="modal-footer" ng-if="!confirm">' + "\n";
    alertTemplate += '<button ng-click="$close()" class="btn btn-primary">Close</button>' + "\n";
    alertTemplate += '</div>' + "\n";

    // alert dialog
    module.alert = function (data) {
        var options = {
            backdrop: true,
            backdropClick: true,
            template: alertTemplate,
            controller: 'AlertDialogController',
            resolve: {
                args: function () {
                    if (!_.isObject(data)) {
                        data = {message: data}
                    }
                    return {
                        data: angular.copy(data)
                    };
                }
            }
        };

        return module.openDialog(options);
    };

    // generic dialog
    module.openDialog = function (options) {
        return $uibModal.open(options);
    };

    return module;
});

// Alert modal dialog controller
plik.controller('AlertDialogController', ['$scope', 'args',
    function ($scope, args) {

        _.extend($scope, args.data);

        if (!$scope.title) {
            if ($scope.status) {
                if ($scope.status === 100) {
                    $scope.title = 'Success !';
                } else {
                    $scope.title = 'Oops ! (' + $scope.status + ')';
                }
            }
        }
    }]);

// HTTP basic auth credentials dialog controller
plik.controller('PasswordController', ['$scope',
    function ($scope) {

        // Ugly but it works
        setTimeout(function () {
            $("#login").focus();
        }, 100);

        $scope.title = 'Please fill credentials !';
        $scope.login = 'user';
        $scope.password = '';

        $scope.close = function (login, password) {
            if (login.length > 0 && password.length > 0) {
                $scope.$close({login: login, password: password});
            }
        };
    }]);

// HTTP basic auth credentials dialog controller
plik.controller('PasteController', ['$scope', 'args',
    function ($scope, args) {
        // Ugly but it works
        setTimeout(function () {
            $("#text").focus();
            var h = (document.documentElement.clientHeight * 70 / 100) + "px";
            $("#text").css('height', h);
        }, 100);

        $scope.title = 'Enter text :';
        $scope.text = args.text

        $scope.close = function (text) {
            if (text.length) {
                $scope.$close({text: text});
            }
        };
    }]);

// HTTP basic auth credentials dialog controller
plik.controller('UserController', ['$scope', 'args', '$config', '$q',
    function ($scope, args, $config, $q) {
        $scope.title = 'User :';

        $scope.edit = false;
        $scope.user = {};
        $scope.warning = null;

        $scope.configReady = $q.defer();
        $config.getConfig()
            .then(function (config) {
                $scope.config = config;
                $scope.configReady.resolve(true);
            }).then(null, function (error) {
                $scope.$close({error: error});
            });

        $scope.userReady = $q.defer();
        $config.getUser()
            .then(function (user) {
                $scope.auth_user = user;
                $scope.userReady.resolve(true);
            }).then(null, function (error) {
                $scope.$close({error: error});
            });


        $scope.maxFileSize = -1;
        $scope.ttlUnits = ttlUnits;
        $scope.ttlUnits[3] = "unlimited";
        $scope.ttlUnit = "days";
        $scope.ttlValue = 30;

        // Set MaxTTL value
        $scope.setMaxTTL = function (ttl) {
            var res = getHumanReadableTTL(ttl)
            $scope.ttlValue = res[0]
            $scope.ttlUnit = $scope.ttlUnits[res[2]];
        };

        $scope.setMaxFileSize = function (maxFileSize) {
            $scope.maxFileSize = getHumanReadableSize(maxFileSize);
        }

        // whenReady ensure that the scope has been initialized especially :
        // $scope.config, $scope.user, $scope.mode, $scope.upload, $scope.files, ...
        $scope.ready = $q.all([$scope.configReady, $scope.userReady]);

        $scope.ready
            .then(function () {
                if (args.user) {
                    // Paranoid useless check
                    if (!$scope.auth_user.admin && args.user.id !== $scope.auth_user.id) {
                        $scope.closeWithError("forbidden")
                        return;
                    }

                    $scope.edit = true;
                    $scope.user = args.user;
                    $scope.setMaxTTL($scope.user.maxTTL);
                    $scope.setMaxFileSize($scope.user.maxFileSize);
                } else {
                    $scope.user.provider = "local";
                    $scope.setMaxTTL(0);
                    $scope.setMaxFileSize(0);
                    $scope.generatePassword();
                }
            }).then(function () {
                // discard
            })

        // Generate random 16 chars
        $scope.generatePassword = function () {
            pass = "";
            for (i=0;i<2;i++) {
                pass += window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36)
            }
            $scope.user.password = pass;
        }

        // Check TTL value
        $scope.checkTTL = function (ttl) {
            // Invalid negative value
            if ($scope.ttlUnit !== 'unlimited' && ttl < 0) {
                $scope.warning = "Invalid max TTL : " + getHumanReadableTTLString(ttl);
                return false;
            }

            return true;
        };

        $scope.check = function(user) {
            $scope.warning = null;

            if (!$scope.edit && (!user.login || user.login.length < 4)) {
                $scope.warning = "invalid login (min 4 chars)";
                return false;
            }

            if ($scope.provider !== "local" || !($scope.edit && !user.password)) {
                console.log("la");
                if (!user.password || user.password.length < 8) {
                    console.log("pala");
                    $scope.warning = "invalid password (min 8 chars)";
                    return false;
                }
            }

            // Get TTL in seconds
            var ttl = getTTL($scope.ttlValue, $scope.ttlUnit);
            if (!$scope.checkTTL(ttl)) {
                return false;
            }
            $scope.user.maxTTL = ttl;

            var maxFileSize = parseHumanReadableSize($scope.maxFileSize, {base: 10});
            if (_.isUndefined(maxFileSize)) {
                $scope.warning = "invalid max file size";
                return false;
            }
            $scope.user.maxFileSize = maxFileSize;

            return true;
        };

        $scope.closeWithError = function (error) {
            $scope.$close({error: error});
        }

        $scope.close = function (user) {
            if ($scope.check(user)) {
                $scope.$close({user: user});
            }
        };
    }]);

// QRCode dialog controller
plik.controller('QRCodeController', ['$scope', 'args',
    function ($scope, args) {
        $scope.args = args;
    }]);