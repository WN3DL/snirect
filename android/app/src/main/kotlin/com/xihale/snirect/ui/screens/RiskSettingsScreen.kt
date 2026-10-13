package com.xihale.snirect.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.xihale.snirect.R
import com.xihale.snirect.data.repository.ConfigRepository
import com.xihale.snirect.ui.components.AppScreenScaffold
import com.xihale.snirect.ui.components.SettingsRiskGroup
import com.xihale.snirect.ui.components.SettingsRiskTile
import com.xihale.snirect.ui.components.SettingsTile
import com.xihale.snirect.ui.theme.SnirectSpacing
import kotlinx.coroutines.launch

@Composable
fun RiskSettingsScreen(
    navController: NavController,
    repository: ConfigRepository
) {
    val scope = rememberCoroutineScope()

    var skipCertCheck by remember { mutableStateOf(false) }
    var checkHostname by remember { mutableStateOf(true) }
    var autoBlacklistEnabled by remember { mutableStateOf(false) }
    var autoExcludedCount by remember { mutableStateOf(0) }

    LaunchedEffect(Unit) { repository.skipCertCheck.collect { skipCertCheck = it } }
    LaunchedEffect(Unit) { repository.checkHostname.collect { checkHostname = it } }
    LaunchedEffect(Unit) { repository.autoBlacklistEnabled.collect { autoBlacklistEnabled = it } }
    LaunchedEffect(Unit) { repository.autoExcludedPackages.collect { autoExcludedCount = it.size } }

    var showHostnameWarningDialog by remember { mutableStateOf(false) }
    var showAutoBlacklistDialog by remember { mutableStateOf(false) }

    AppScreenScaffold(
        title = stringResource(R.string.risk_settings_title),
        onBack = { navController.popBackStack() },
        backContentDescription = stringResource(R.string.action_back)
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = SnirectSpacing.marginMobile, vertical = SnirectSpacing.medium),
            verticalArrangement = Arrangement.spacedBy(SnirectSpacing.large)
        ) {
            SettingsRiskGroup(title = stringResource(R.string.group_high_risk)) {
                SettingsRiskTile(
                    title = stringResource(R.string.setting_skip_cert_check),
                    subtitle = stringResource(R.string.setting_skip_cert_check_warning),
                    checked = skipCertCheck,
                    onCheckedChange = {
                        skipCertCheck = it
                        scope.launch { repository.setSkipCertCheck(it) }
                    }
                )

                HorizontalDivider(color = MaterialTheme.colorScheme.error.copy(alpha = 0.15f), thickness = 1.dp)

                SettingsRiskTile(
                    title = stringResource(R.string.setting_check_hostname),
                    subtitle = if (checkHostname) stringResource(R.string.setting_check_hostname_desc)
                    else stringResource(R.string.setting_check_hostname_warning),
                    checked = checkHostname,
                    onCheckedChange = {
                        if (!it) {
                            showHostnameWarningDialog = true
                        } else {
                            checkHostname = true
                            scope.launch { repository.setCheckHostname(true) }
                        }
                    }
                )
            }

            SettingsRiskGroup(title = stringResource(R.string.group_auto_blacklist)) {
                SettingsRiskTile(
                    title = stringResource(R.string.setting_auto_blacklist),
                    subtitle = if (autoBlacklistEnabled) stringResource(R.string.setting_auto_blacklist_desc)
                    else stringResource(R.string.setting_auto_blacklist_off),
                    checked = autoBlacklistEnabled,
                    onCheckedChange = {
                        if (it) {
                            showAutoBlacklistDialog = true
                        } else {
                            autoBlacklistEnabled = false
                            scope.launch { repository.setAutoBlacklistEnabled(false) }
                        }
                    }
                )

                HorizontalDivider(color = MaterialTheme.colorScheme.error.copy(alpha = 0.15f), thickness = 1.dp)

                SettingsTile(
                    icon = Icons.Outlined.Block,
                    title = stringResource(R.string.auto_exclude_title),
                    subtitle = stringResource(R.string.auto_exclude_apps_count, autoExcludedCount),
                    onClick = { navController.navigate("auto_excluded") },
                    showChevron = true
                )
            }
        }
    }

    // Hostname Security Warning Dialog
    if (showHostnameWarningDialog) {
        AlertDialog(
            onDismissRequest = { showHostnameWarningDialog = false },
            icon = {
                Icon(
                    Icons.Outlined.WarningAmber,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error
                )
            },
            title = { Text(stringResource(R.string.security_warning_title)) },
            text = { Text(stringResource(R.string.security_warning_msg)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        checkHostname = false
                        scope.launch { repository.setCheckHostname(false) }
                        showHostnameWarningDialog = false
                    }
                ) {
                    Text(
                        text = stringResource(R.string.action_disable_anyway),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showHostnameWarningDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
        )
    }

    // Auto-Blacklist Enable Confirmation: states the restart blip up front.
    if (showAutoBlacklistDialog) {
        AlertDialog(
            onDismissRequest = { showAutoBlacklistDialog = false },
            title = { Text(stringResource(R.string.auto_blacklist_enable_title)) },
            text = { Text(stringResource(R.string.auto_blacklist_enable_msg)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        autoBlacklistEnabled = true
                        scope.launch { repository.setAutoBlacklistEnabled(true) }
                        showAutoBlacklistDialog = false
                    }
                ) {
                    Text(stringResource(R.string.action_enable))
                }
            },
            dismissButton = {
                TextButton(onClick = { showAutoBlacklistDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
        )
    }
}
