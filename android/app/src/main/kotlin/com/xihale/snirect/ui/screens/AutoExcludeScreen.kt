package com.xihale.snirect.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.xihale.snirect.R
import com.xihale.snirect.data.repository.ConfigRepository
import com.xihale.snirect.ui.components.AppEmptyState
import com.xihale.snirect.ui.components.AppScreenScaffold
import com.xihale.snirect.ui.components.AppTopBarStyle
import com.xihale.snirect.ui.theme.SnirectSpacing
import kotlinx.coroutines.launch

/**
 * Review screen for apps the engine auto-excluded (cert-pinned clients that
 * kept rejecting the proxy certificate). Removal immediately un-excludes the
 * app: the next VPN start captures it again.
 */
@Composable
fun AutoExcludeScreen(
    navController: NavController,
    repository: ConfigRepository
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var excluded by remember { mutableStateOf(setOf<String>()) }
    var appInfo by remember { mutableStateOf<Map<String, AppItem>>(emptyMap()) }

    LaunchedEffect(Unit) {
        repository.autoExcludedPackages.collect { excluded = it }
    }
    LaunchedEffect(Unit) {
        val cached = InstalledAppsCache.peek()?.apps ?: InstalledAppsCache.load(context).apps
        appInfo = cached.associateBy { it.packageName }
    }

    AppScreenScaffold(
        title = stringResource(R.string.auto_exclude_title),
        onBack = { navController.popBackStack() },
        backContentDescription = stringResource(R.string.action_back),
        topBarStyle = AppTopBarStyle.Top,
        header = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = stringResource(R.string.auto_exclude_apps_count, excluded.size),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                if (excluded.isNotEmpty()) {
                    TextButton(onClick = {
                        scope.launch { repository.setAutoExcludedPackages(emptySet()) }
                    }) {
                        Text(stringResource(R.string.auto_exclude_clear_all))
                    }
                }
            }
        }
    ) { padding ->
        if (excluded.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                AppEmptyState(
                    icon = Icons.Outlined.Shield,
                    title = stringResource(R.string.auto_exclude_empty_title),
                    supportingText = stringResource(R.string.auto_exclude_empty_hint)
                )
            }
            return@AppScreenScaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = SnirectSpacing.marginMobile,
                top = SnirectSpacing.gutter,
                end = SnirectSpacing.marginMobile,
                bottom = SnirectSpacing.xxLarge
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(excluded.sorted(), key = { it }) { pkg ->
                val info = appInfo[pkg]
                AutoExcludeItem(
                    packageName = pkg,
                    label = info?.label ?: pkg,
                    icon = info?.icon,
                    onRemove = {
                        scope.launch { repository.setAutoExcludedPackages(excluded - pkg) }
                    }
                )
            }
        }
    }
}

@Composable
private fun AutoExcludeItem(
    packageName: String,
    label: String,
    icon: ImageBitmap?,
    onRemove: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                modifier = Modifier.size(44.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    if (icon != null) {
                        Image(
                            bitmap = icon,
                            contentDescription = label,
                            modifier = Modifier.size(32.dp)
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Outlined.Apps,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            IconButton(onClick = onRemove) {
                Icon(
                    imageVector = Icons.Outlined.Close,
                    contentDescription = stringResource(R.string.action_cancel),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
