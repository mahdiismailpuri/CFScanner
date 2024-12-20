package ir.filternet.cfscanner.ui.page.main.scan

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Webhook
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import ir.filternet.cfscanner.contracts.SIDE_EFFECTS_KEY
import ir.filternet.cfscanner.model.ScanButtonState
import ir.filternet.cfscanner.service.CloudScannerService
import ir.filternet.cfscanner.ui.common.ScanningDetailsView
import ir.filternet.cfscanner.ui.page.main.scan.component.CloudLogo
import ir.filternet.cfscanner.ui.page.main.scan.component.ConfigEditDialog
import ir.filternet.cfscanner.ui.page.main.scan.component.ConfigSelectionBox
import ir.filternet.cfscanner.ui.page.main.scan.component.LoadingView
import ir.filternet.cfscanner.ui.page.main.scan.component.LogBox
import ir.filternet.cfscanner.ui.page.main.scan.component.NotificationPermissionRequest
import ir.filternet.cfscanner.ui.page.main.scan.component.ScanButton
import ir.filternet.cfscanner.utils.isNotificationEnabled
import ir.filternet.cfscanner.utils.parseToCommonName
import ir.filternet.cfscanner.utils.tryStartForegroundService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach

@Composable
fun ScanScreen(
    state: ScanContract.State,
    effectFlow: Flow<ScanContract.Effect>?,
    onEventSent: (event: ScanContract.Event) -> Unit,
    onNavigationRequested: (navigationEffect: ScanContract.Effect.Navigation) -> Unit,
) {

    var configEdit by remember { mutableStateOf(state.configEdit) }
    val context = LocalContext.current
    LaunchedEffect(SIDE_EFFECTS_KEY) {
        effectFlow?.onEach { effect ->
            when (effect) {
                is ScanContract.Effect.Messenger -> {
                    when (effect) {
                        is ScanContract.Effect.Messenger.Toast -> {
                            val message = effect.message ?: context.getString(effect.messageId!!)
                            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
                        }
                    }
                }
                is ScanContract.Effect.Navigation -> {
                    onNavigationRequested(effect)
                }
                is ScanContract.Effect.Dialog.ConfigEditDialog -> {
                    configEdit = effect.config
                }
                else -> {}
            }
        }?.collect()
    }


    val log = state.logs
    val configs = state.configs
    val loading = state.loading
    val buttonState = state.buttonState
    val dismissNotification = state.dismissNotificationDialog
    val scanning = state.buttonState is ScanButtonState.Scanning

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(bottom = 60.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Spacer(modifier = Modifier.height(15.dp))

            CloudLogo(scanning) {

            }

            Spacer(modifier = Modifier.height(15.dp))

            if (!loading) {


                if (buttonState is ScanButtonState.Scanning) {
                    val scan = buttonState.scan
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(bottom = 5.dp), horizontalArrangement = Arrangement.SpaceAround
                    ) {
                        ScanningDetailsView(Icons.Rounded.Language, scan.isp.parseToCommonName(context))
                        ScanningDetailsView(Icons.Rounded.Webhook, scan.config.name)
                    }

                    Spacer(modifier = Modifier.height(15.dp))

                    LogBox(Modifier.fillMaxSize(), log){
                        onEventSent.invoke(ScanContract.Event.SkipCurrentRange)
                    }
                }

                if (buttonState !is ScanButtonState.Scanning)
                    ConfigSelectionBox(configs, {
                        onEventSent(ScanContract.Event.SelectConfig(it))
                    }, {
                        configEdit = it
                    }) {
                        onEventSent(ScanContract.Event.AddConfig(it))
                    }

            } else {
                LoadingView()
            }
        }

        ScanButton(state = if (loading || configs.isEmpty()) ScanButtonState.Disabled() else buttonState) {
            when (buttonState) {
                is ScanButtonState.Scanning -> {
                    onEventSent(ScanContract.Event.StopScan)
                }
                is ScanButtonState.Ready, is ScanButtonState.Paused -> {
                    context.tryStartForegroundService(CloudScannerService::class.java)
                    onEventSent(ScanContract.Event.StartScan)
                }
                else -> {}
            }
        }

    }

    if (configEdit != null)
        ConfigEditDialog(configEdit!!,
            { onEventSent(ScanContract.Event.UpdateConfig(it)) },
            { onEventSent(ScanContract.Event.DeleteConfig(it)) },
            { configEdit = null }
        )


    /* show notification permission Dialog */
    var showPermissionDialog by remember { mutableStateOf(false) }

    if (showPermissionDialog)
        NotificationPermissionRequest {
            showPermissionDialog = false
            onEventSent.invoke(ScanContract.Event.DisableNotificationDialog)
        }

    LaunchedEffect(Unit) {
        if (!context.isNotificationEnabled() && !dismissNotification) {
            showPermissionDialog = true
        }
    }
    /* end show notification permission Dialog */

}